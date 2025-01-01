#define _GNU_SOURCE
#include "db.h"
#include <assert.h>
#include <errno.h>
#include <glib-object.h>
#include <glib-unix.h>
#include <grp.h>
#include <jansson.h>
#include <libsoup/soup-server-message.h>
#include <libsoup/soup-server.h>
#include <nftables/libnftables.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static const char *NFT_ALLOW_TEMPLATE = "insert rule ip filter INPUT index 0 tcp dport %d counter accept";
static const char *NFT_DENY_TEMPLATE = "delete rule ip filter INPUT handle %u";

static const uint16_t DEFAULT_PORT = 22;
static const uint16_t DEFAULT_HTTP_PORT = 8089;
static const uint DEFAULT_TIMEOUT_S = 60;
static const char *DEFAULT_DROP_USER = "nobody";

G_DEFINE_AUTOPTR_CLEANUP_FUNC(json_t, json_decref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(FILE, fclose)

typedef struct {
    uint16_t port;
    uint timeout_s;
    uint16_t http_port;
    char *db_path;
    char *drop_user;
} knock_config;

typedef struct {
    knock_config conf;
    int nft_sk;
    sqlite3 *sqlite_db;
    uint delete_timeout_handle;
    uint nft_handle;
} knock_context;

typedef struct {
    bool is_err;
    uint msg_len;
    char message_text[];
} knock_ipc_message;

/* a mutex that uses glib main loop to block */
typedef struct {
    bool locked;
} main_loop_mutex;

static char *nft_run_with_json_output(struct nft_ctx *nft, const char *command)
{
    char *result = NULL;

    int flags = nft_ctx_output_get_flags(nft);
    nft_ctx_output_set_flags(nft, flags | NFT_CTX_OUTPUT_JSON | NFT_CTX_OUTPUT_ECHO);

    if (nft_ctx_buffer_output(nft)) {
        fprintf(stderr, "nft_ctx_buffer_output failed\n");
        return NULL;
    }

    if (nft_run_cmd_from_buffer(nft, command)) {
        /* libnftables will print error details to stderr */
        fprintf(stderr, "nft_run_cmd_from_buffer failed\n");
        goto err;
    }

    result = strdup(nft_ctx_get_output_buffer(nft));

err:
    nft_ctx_unbuffer_output(nft);
    nft_ctx_output_set_flags(nft, flags & ~(NFT_CTX_OUTPUT_JSON | NFT_CTX_OUTPUT_ECHO));

    return result;
}

static void send_ipc_message(int fd, bool is_err, const char *message_text, ...)
{
    g_autofree char *formatted_message = NULL;
    if (message_text) {
        va_list ap;
        va_start(ap, message_text);
        assert(vasprintf(&formatted_message, message_text, ap) >= 0);
        va_end(ap);
    }

    g_debug("send_ipc_message: formatted_message: %s\n", formatted_message);

    uint msg_len = formatted_message ? strlen(formatted_message) + 1 : 1;
    uint total_len = sizeof(knock_ipc_message) + msg_len;
    assert(total_len < 1 << 24);
    g_autofree knock_ipc_message *msg = calloc(1, total_len);
    assert(msg != NULL);

    msg->is_err = is_err;
    msg->msg_len = msg_len;
    if (formatted_message)
        strcpy(msg->message_text, formatted_message);

    int n_written;
    n_written = write(fd, &total_len, sizeof(total_len));
    assert(n_written == sizeof(total_len));
    n_written = write(fd, msg, total_len);
    assert(n_written == (int)total_len);
}

static knock_ipc_message *receive_ipc_message(int fd)
{
    uint total_len;
    int n_read = read(fd, &total_len, sizeof(total_len));
    if (n_read < 0) {
        fprintf(stderr, "proc read failed: %m\n");
        abort();
    } else if (n_read == 0) {
        printf("ipc connection lost\n");
        return NULL;
    }
    assert(n_read == sizeof(total_len));
    assert(total_len < 65536);

    knock_ipc_message *msg = malloc(total_len);
    assert(msg != NULL);
    n_read = read(fd, msg, total_len);
    assert(n_read == (int)total_len);

    return msg;
}

static void main_loop_mutex_lock(main_loop_mutex *mutex)
{
    GMainContext *main_context = g_main_context_default();
    while (mutex->locked)
        g_main_context_iteration(main_context, true);
    mutex->locked = true;
}

static void main_loop_mutex_unlock(main_loop_mutex *mutex) { mutex->locked = false; }

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(main_loop_mutex, main_loop_mutex_unlock)

static char *run_nft_command_in_subprocess(int sk, const char *command)
{
    send_ipc_message(sk, false, "%s\n", command);

    g_autofree knock_ipc_message *msg = receive_ipc_message(sk);
    if (!msg)
        return NULL;
    if (msg->is_err) {
        fprintf(stderr, "failed to run nft command: %s\n", msg->message_text);
        return NULL;
    }

    return strdup(msg->message_text);
}

static void try_delete_nft_rule(knock_context *ctx)
{
    if (!ctx->nft_handle)
        return;

    g_debug("removing nft rule...\n");

    char nft_script[256];
    snprintf(nft_script, sizeof(nft_script), NFT_DENY_TEMPLATE, ctx->nft_handle);
    g_autofree char *result = run_nft_command_in_subprocess(ctx->nft_sk, nft_script);
    if (!result)
        fprintf(stderr, "failed to delete nft rule\n");
    else
        ctx->nft_handle = 0;

    printf("firewall rule removed\n");
}

static int delete_rule_timeout_func(void *user_data)
{
    knock_context *ctx = user_data;

    try_delete_nft_rule(ctx);

    ctx->delete_timeout_handle = 0;
    return false;
}

static const char *parse_auth_header(SoupServerMessage *msg)
{
    SoupMessageHeaders *headers = soup_server_message_get_request_headers(msg);
    const char *auth_header = soup_message_headers_get_one(headers, "authorization");
    if (!auth_header) {
        fprintf(stderr, "authentication failed: missing header\n");
        goto err;
    }

    const char *prefix = "bearer ";
    if (strncasecmp(auth_header, prefix, strlen(prefix))) {
        fprintf(stderr, "authentication failed: invalid auth type\n");
        goto err;
    }

    const char *auth_key = auth_header + strlen(prefix);
    if (strlen(auth_key) > 64) {
        fprintf(stderr, "authentication failed: header too long\n");
        goto err;
    }

    return auth_key;

err:
    soup_server_message_set_status(msg, SOUP_STATUS_UNAUTHORIZED, NULL);
    return NULL;
}

static bool handle_auth(SoupServerMessage *msg, knock_context *ctx, char **auth_name)
{
    assert(auth_name != NULL);

    bool retval = false;

    const char *auth_key = parse_auth_header(msg);
    if (!auth_key)
        return false;

    const char *sql = "SELECT name FROM auth WHERE key = ? LIMIT 1";
    sqlite3_stmt *stmt = NULL;
    int res = sqlite3_prepare_v2(ctx->sqlite_db, sql, -1, &stmt, NULL);
    if (res) {
        fprintf(stderr, "failed to execute sql query: %s\n", sqlite3_errstr(res));
        soup_server_message_set_status(msg, SOUP_STATUS_INTERNAL_SERVER_ERROR, NULL);
        return false;
    }

    res = sqlite3_bind_text(stmt, 1, auth_key, -1, SQLITE_STATIC);
    assert(res == SQLITE_OK);

    res = sqlite3_step(stmt);
    if (res == SQLITE_ROW) {
        g_debug("authentication successful\n");
        *auth_name = strdup((char *)sqlite3_column_text(stmt, 0));
        retval = true;
    } else if (res == SQLITE_DONE) {
        fprintf(stderr, "authentication failed: unknown key\n");
        soup_server_message_set_status(msg, SOUP_STATUS_UNAUTHORIZED, NULL);
    } else {
        fprintf(stderr, "failed to execute sql query: %s\n", sqlite3_errstr(res));
        soup_server_message_set_status(msg, SOUP_STATUS_INTERNAL_SERVER_ERROR, NULL);
    }

    sqlite3_finalize(stmt);

    return retval;
}

static int get_nft_handle_from_json(const char *json)
{
    json_error_t error;
    g_autoptr(json_t) root = json_loads(json, 0, &error);
    if (!root) {
        fprintf(stderr, "failed to parse json: %s\n", error.text);
        return -1;
    }

    json_t *n = json_object_get(root, "nftables");
    if (!n || !json_is_array(n))
        goto err;
    json_t *ary = json_array_get(n, 0);
    if (!ary)
        goto err;
    json_t *i = json_object_get(ary, "insert");
    if (!i)
        goto err;
    json_t *r = json_object_get(i, "rule");
    if (!r)
        goto err;
    json_t *handle_ptr = json_object_get(r, "handle");
    if (!handle_ptr || !json_is_integer(handle_ptr))
        goto err;

    return json_integer_value(handle_ptr);

err:
    fprintf(stderr, "malformed nft json output: %s\n", json);
    return -1;
}

static void knock_handler(__attribute__((unused)) SoupServer *server, SoupServerMessage *msg, const char *path,
                          __attribute__((unused)) GHashTable *query, void *user_data)
{
    knock_context *ctx = user_data;

    /* libsoup routing uses prefixes. make sure we match by exact path
       name */
    if (strcmp(path, "/knock")) {
        soup_server_message_set_status(msg, SOUP_STATUS_NOT_FOUND, NULL);
        return;
    }

    g_autofree char *auth_name = NULL;
    if (!handle_auth(msg, ctx, &auth_name))
        return;

    const char *method = soup_server_message_get_method(msg);

    printf("%s %s [auth_name=%s]\n", method, path, auth_name);

    if (method != SOUP_METHOD_POST) {
        soup_server_message_set_status(msg, SOUP_STATUS_NOT_IMPLEMENTED, NULL);
        return;
    }

    g_auto(main_loop_mutex) lock = {0};
    main_loop_mutex_lock(&lock);

    if (!ctx->nft_handle) {
        char nft_script[256];
        snprintf(nft_script, sizeof(nft_script), NFT_ALLOW_TEMPLATE, ctx->conf.port);
        g_autofree char *json_output = run_nft_command_in_subprocess(ctx->nft_sk, nft_script);
        if (!json_output) {
            fprintf(stderr, "failed to create nft rule\n");
            soup_server_message_set_status(msg, SOUP_STATUS_INTERNAL_SERVER_ERROR, NULL);
            return;
        }
        int nft_handle = get_nft_handle_from_json(json_output);
        if (nft_handle < 0) {
            soup_server_message_set_status(msg, SOUP_STATUS_INTERNAL_SERVER_ERROR, NULL);
            return;
        }
        ctx->nft_handle = nft_handle;
    } else {
        g_debug("nft entry already exists\n");
    }

    if (ctx->delete_timeout_handle) {
        g_debug("cancelling previous timeout\n");
        g_source_remove(ctx->delete_timeout_handle);
        ctx->delete_timeout_handle = 0;
    }
    ctx->delete_timeout_handle = g_timeout_add_seconds(ctx->conf.timeout_s, delete_rule_timeout_func, ctx);

    soup_server_message_set_status(msg, SOUP_STATUS_OK, NULL);
    const char *resp = "{\"status\": \"ok\"}";
    soup_server_message_set_response(msg, "application/json", SOUP_MEMORY_COPY, resp, strlen(resp));
}

[[noreturn]]
static int handle_unix_signals(void *user_data)
{
    knock_context *ctx = user_data;

    try_delete_nft_rule(ctx);

    exit(0);
    g_assert_not_reached();
}

static bool drop_perms(const char *username)
{
    errno = 0;
    struct passwd *pwd = getpwnam(username);
    if (!pwd) {
        if (errno)
            fprintf(stderr, "unable to read /etc/passwd: %m\n");
        else
            fprintf(stderr, "user '%s' not found\n", username);
        return false;
    }

    if (setgid(pwd->pw_gid) < 0) {
        fprintf(stderr, "setgid failed: %m\n");
        return false;
    }
    if (setuid(pwd->pw_uid) < 0) {
        fprintf(stderr, "setuid failed: %m\n");
        return false;
    }

    return true;
}

static void nft_process(int sk)
{
    struct nft_ctx *libnft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!libnft) {
        send_ipc_message(sk, true, "failed to initialize libnft context");
        return;
    }

    send_ipc_message(sk, false, NULL);

    sigset_t sig;
    sigemptyset(&sig);
    sigaddset(&sig, SIGTERM);
    sigaddset(&sig, SIGINT);
    if (sigprocmask(SIG_BLOCK, &sig, NULL) < 0) {
        send_ipc_message(sk, true, "failed to block signals");
        exit(1);
    }

    while (true) {
        g_autofree knock_ipc_message *msg = receive_ipc_message(sk);
        if (!msg)
            break;

        g_autofree char *output = nft_run_with_json_output(libnft, msg->message_text);
        if (output)
            send_ipc_message(sk, false, output);
        else
            send_ipc_message(sk, true, "nft call failed");
    }

    nft_ctx_free(libnft);

    exit(0);
}

static int spawn_nft_process(void)
{
    int sks[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sks) < 0) {
        fprintf(stderr, "socketpair failed: %m\n");
        return -1;
    }

    pid_t pid = fork();
    if (pid == 0) {
        close(sks[1]);
        nft_process(sks[0]);
        g_assert_not_reached();
    } else {
        close(sks[0]);

        g_autofree knock_ipc_message *msg = receive_ipc_message(sks[1]);
        if (!msg || msg->is_err) {
            fprintf(stderr, "failed to spawn nft process: %s\n", msg->message_text);
            close(sks[1]);
            return -1;
        }
    }

    return sks[1];
}

static bool read_config(knock_config *conf, int *argc, char **argv[])
{
    conf->port = DEFAULT_PORT;
    conf->timeout_s = DEFAULT_TIMEOUT_S;
    conf->http_port = DEFAULT_HTTP_PORT;

    int port = 0;
    int http_port = 0;

    GOptionEntry entries[] = {
        {"port", 'p', 0, G_OPTION_ARG_INT, &port, "Port to open", "P"},
        {"timeout", 0, 0, G_OPTION_ARG_INT, &conf->timeout_s, "Timeout in second after port is blocked again", "S"},
        {"http-port", 0, 0, G_OPTION_ARG_INT, &http_port, "Listen port", "P"},
        {"db-path", 0, 0, G_OPTION_ARG_STRING, &conf->db_path, "Path to state db", NULL},
        {"user", 0, 0, G_OPTION_ARG_STRING, &conf->drop_user, "Run as user", NULL},
        G_OPTION_ENTRY_NULL};

    g_autoptr(GOptionContext) context = g_option_context_new("- port knocking http daemon");
    g_option_context_add_main_entries(context, entries, NULL);

    g_autoptr(GError) error = NULL;
    if (!g_option_context_parse(context, argc, argv, &error)) {
        fprintf(stderr, "failed to parse command line args: %s\n", error->message);
        return false;
    }

    if (port) {
        if (port < 0 || port >= 1 << 16) {
            fprintf(stderr, "port number of out range: %d\n", port);
            return false;
        }
        conf->port = port;
    }
    if (http_port) {
        if (http_port < 0 || http_port >= 1 << 16) {
            fprintf(stderr, "port number of out range: %d\n", http_port);
            return false;
        }
        conf->http_port = http_port;
    }

    if (!conf->db_path)
        conf->db_path = strdup(DEFAULT_DB_PATH);
    if (!conf->drop_user)
        conf->drop_user = strdup(DEFAULT_DROP_USER);

    return true;
}

static void print_config(knock_config *conf)
{
    printf("Port: %u\n", conf->port);
    printf("Timeout: %u\n", conf->timeout_s);
    printf("Listen port: %u\n", conf->http_port);
    printf("Database path: %s\n", conf->db_path);
}

static void knock_config_deinit(knock_config *conf)
{
    free(conf->db_path);
    free(conf->drop_user);
}

static void knock_context_deinit(knock_context *ctx)
{
    if (!ctx)
        return;
    if (ctx->sqlite_db)
        sqlite3_close(ctx->sqlite_db);
    if (ctx->nft_sk)
        close(ctx->nft_sk);
    knock_config_deinit(&ctx->conf);
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(knock_context, knock_context_deinit)

int main(int argc, char *argv[])
{
    g_autoptr(GError) error = NULL;
    g_auto(knock_context) ctx = {0};

    setlinebuf(stdout);
    setlinebuf(stderr);

    if (!read_config(&ctx.conf, &argc, &argv))
        return 1;
    print_config(&ctx.conf);

    ctx.sqlite_db = open_sqlite_connection(ctx.conf.db_path);
    if (!ctx.sqlite_db)
        return 1;

    ctx.nft_sk = spawn_nft_process();
    if (ctx.nft_sk < 0)
        return 1;

    if (!drop_perms(ctx.conf.drop_user)) {
        fprintf(stderr, "failed to drop permissions\n");
        return 1;
    }

    g_autoptr(SoupServer) server = soup_server_new(NULL, NULL);

    soup_server_add_handler(server, "/knock", knock_handler, &ctx, NULL);

    g_unix_signal_add(SIGTERM, handle_unix_signals, &ctx);
    g_unix_signal_add(SIGINT, handle_unix_signals, &ctx);

    if (!soup_server_listen_local(server, ctx.conf.http_port, 0, &error)) {
        fprintf(stderr, "listen failed: %s\n", error->message);
        return 1;
    }

    GMainLoop *loop = g_main_loop_new(NULL, false);
    g_main_loop_run(loop);
    g_main_loop_unref(loop);

    return 0;
}
