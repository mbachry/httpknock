#define _GNU_SOURCE
#include "db.h"
#include <assert.h>
#include <stdio.h>
#include <sys/stat.h>

static const char *CREATE_SQL_TABLE = "CREATE TABLE IF NOT EXISTS auth (id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT "
                                      "NULL, key TEXT NOT NULL, last_login DATETIME);";

static const char *ADD_COLUMN_SQL = "ALTER TABLE auth ADD COLUMN last_login DATETIME;";

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

    /* migrate to "last_login" column if necessary */
    sqlite3_stmt *stmt = NULL;
    const char *check_column_sql = "SELECT 1 FROM pragma_table_info('auth') WHERE name='last_login';";
    res = sqlite3_prepare_v2(db, check_column_sql, -1, &stmt, NULL);
    assert(res == SQLITE_OK);
    res = sqlite3_step(stmt);
    bool column_exists = (res == SQLITE_ROW);
    sqlite3_finalize(stmt);
    if (!column_exists) {
        if (sqlite3_exec(db, ADD_COLUMN_SQL, NULL, NULL, &sql_error)) {
            assert(sql_error);
            fprintf(stderr, "failed to add last_login column: %s\n", sql_error);
            sqlite3_free(sql_error);
            sqlite3_close(db);
            return NULL;
        }
    }

    return db;
}
