#define _GNU_SOURCE
#include "db.h"
#include <assert.h>
#include <stdio.h>
#include <sys/stat.h>

static const char *CREATE_SQL_TABLE =
    "CREATE TABLE IF NOT EXISTS auth (id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL, key TEXT NOT NULL);";

sqlite3 *open_sqlite_connection(const char *db_path)
{
    sqlite3 *db;
    int res = sqlite3_open(db_path, &db);
    if (res) {
        fprintf(stderr, "failed to open sqlite database: %s: %s (%m)\n", db_path, sqlite3_errstr(res));
        return NULL;
    }

    if (chmod(db_path, 0600) < 0) {
        fprintf(stderr, "failed to fix sqlite db permissions: %m\n");
        sqlite3_close(db);
        return NULL;
    }

    char *sql_error = NULL;
    if (sqlite3_exec(db, CREATE_SQL_TABLE, NULL, NULL, &sql_error)) {
        assert(sql_error);
        fprintf(stderr, "failed to ensure db table: %s\n", sql_error);
        sqlite3_free(sql_error);
        sqlite3_close(db);
        return NULL;
    }

    return db;
}
