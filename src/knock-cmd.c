#define _GNU_SOURCE
#include <assert.h>
#include <glib.h>
#include <libsoup/soup.h>
#include <stdio.h>
#include <sys/random.h>

int main(int argc, char *argv[])
{
    g_autoptr(GError) error = NULL;
    g_autofree char *conf_path = NULL;

    GOptionEntry entries[] = {
        {"config-path", 0, 0, G_OPTION_ARG_STRING, &conf_path, "Path to configuration file", NULL},
        G_OPTION_ENTRY_NULL};

    g_autoptr(GOptionContext) context = g_option_context_new(" - knock a server");
    g_option_context_add_main_entries(context, entries, NULL);
    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        fprintf(stderr, "failed to parse command line args: %s\n", error->message);
        return 1;
    }

    if (!conf_path) {
        const char *xdg_conf_dir = g_get_user_config_dir();
        conf_path = g_build_filename(xdg_conf_dir, "httpknock.conf", NULL);
    }

    g_autoptr(GKeyFile) key_file = g_key_file_new();
    if (!g_key_file_load_from_file(key_file, conf_path, 0, &error)) {
        fprintf(stderr, "failed to read config: %s: %s\n", conf_path, error->message);
        return 1;
    }

    g_autofree char *url = g_key_file_get_string(key_file, "httpknock", "url", &error);
    if (url == NULL) {
        fprintf(stderr, "missing or invalid config entry: %s\n", error->message);
        return 1;
    }
    g_autofree char *auth_key = g_key_file_get_string(key_file, "httpknock", "key", &error);
    if (auth_key == NULL) {
        fprintf(stderr, "missing or invalid config entry: %s\n", error->message);
        return 1;
    }

    g_autoptr(SoupSession) session = soup_session_new();
    g_autoptr(SoupMessage) msg = soup_message_new(SOUP_METHOD_POST, url);

    SoupMessageHeaders *request_headers = soup_message_get_request_headers(msg);
    g_autofree char *auth_header = NULL;
    assert(asprintf(&auth_header, "bearer %s", auth_key) > 0);
    soup_message_headers_replace(request_headers, "Authorization", auth_header);

    g_autofree GBytes *bytes = soup_session_send_and_read(session, msg, NULL, &error);
    if (!bytes) {
        fprintf(stderr, "http call failed: %s\n", error->message);
        return 1;
    }

    SoupStatus status = soup_message_get_status(msg);
    if (status != SOUP_STATUS_OK) {
        fprintf(stderr, "http call failed: %d %s\n", status, soup_status_get_phrase(status));
        return 1;
    }

    return 0;
}
