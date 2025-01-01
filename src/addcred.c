#define _GNU_SOURCE
#include "db.h"
#include <assert.h>
#include <glib.h>
#include <stdio.h>
#include <sys/random.h>

G_DEFINE_AUTOPTR_CLEANUP_FUNC(sqlite3, sqlite3_close)

int main(int argc, char *argv[])
{
    char *db_path = DEFAULT_DB_PATH;

    GOptionEntry entries[] = {{"db-path", 0, 0, G_OPTION_ARG_STRING, &db_path, "Path to state db", NULL},
                              G_OPTION_ENTRY_NULL};

    g_autoptr(GOptionContext) context = g_option_context_new("NAME - add knock credential");
    g_option_context_add_main_entries(context, entries, NULL);
    g_autoptr(GError) error = NULL;
    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        fprintf(stderr, "failed to parse command line args: %s\n", error->message);
        return 1;
    }

    if (argc != 2) {
        fprintf(stderr, "missing or invalid arguments\n");
        return 1;
    }
    char *auth_name = argv[1];

    g_autoptr(sqlite3) db = open_sqlite_connection(db_path);
    if (!db)
        return 1;

    unsigned char auth_bytes[32];
    if (getrandom(auth_bytes, sizeof(auth_bytes), 0) < 0) {
        fprintf(stderr, "failed to generate random key: %m\n");
        return 1;
    }
    g_autofree char *auth_key = g_base64_encode(auth_bytes, sizeof(auth_bytes));

    const char *sql = "INSERT INTO auth (name, key) VALUES(?, ?)";
    sqlite3_stmt *stmt = NULL;
    int res = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (res) {
        fprintf(stderr, "failed to execute sql query: %s\n", sqlite3_errstr(res));
        return 1;
    }

    res = sqlite3_bind_text(stmt, 1, auth_name, -1, SQLITE_STATIC);
    assert(res == SQLITE_OK);
    res = sqlite3_bind_text(stmt, 2, auth_key, -1, SQLITE_STATIC);
    assert(res == SQLITE_OK);

    res = sqlite3_step(stmt);
    assert(res != SQLITE_ROW);
    if (res != SQLITE_DONE) {
        fprintf(stderr, "failed to execute sql query: %s\n", sqlite3_errstr(res));
        return 1;
    }
    sqlite3_finalize(stmt);

    printf("generated key: %s\n", auth_key);

    return 0;
}
