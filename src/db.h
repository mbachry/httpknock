#pragma once

#include <sqlite3.h>

#define DEFAULT_DB_PATH "/var/lib/httpknock/db"

sqlite3 *open_sqlite_connection(const char *db_path);
