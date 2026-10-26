"""Storage layer: MySQL (default) or SQLite (zero-setup demo / tests).

Select with the DB_BACKEND environment variable ("mysql" or "sqlite").
MySQL credentials come from DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME -
never hard-code them.
"""

from __future__ import annotations

import os
import random
import sqlite3

_MYSQL_SCHEMA = """
CREATE TABLE IF NOT EXISTS data_table (
    data_id        INT AUTO_INCREMENT PRIMARY KEY,
    number_data    INT NOT NULL,
    encrypted_data BLOB NULL,
    hash_sha256    CHAR(64) NULL,
    updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)"""

_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS data_table (
    data_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    number_data    INTEGER NOT NULL,
    encrypted_data BLOB NULL,
    hash_sha256    TEXT NULL,
    updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)"""


class Database:
    def __init__(self, backend: str | None = None):
        self.backend = (backend or os.environ.get("DB_BACKEND", "mysql")).lower()
        if self.backend == "sqlite":
            self.conn = sqlite3.connect(os.environ.get("SQLITE_PATH", "project_data.db"))
            self._ph = "?"
        elif self.backend == "mysql":
            import mysql.connector  # imported lazily so SQLite users don't need it

            name = os.environ.get("DB_NAME", "project_data")
            kwargs = dict(
                host=os.environ.get("DB_HOST", "localhost"),
                port=int(os.environ.get("DB_PORT", "3306")),
                user=os.environ.get("DB_USER", "root"),
                password=os.environ.get("DB_PASSWORD", ""),
            )
            boot = mysql.connector.connect(**kwargs)
            boot.cursor().execute(f"CREATE DATABASE IF NOT EXISTS `{name}`")
            boot.close()
            self.conn = mysql.connector.connect(database=name, **kwargs)
            self._ph = "%s"
        else:
            raise ValueError("DB_BACKEND must be 'mysql' or 'sqlite'")

    def _run(self, sql: str, params: tuple = ()):
        cur = self.conn.cursor()
        cur.execute(sql.replace("?", self._ph), params)
        return cur

    def init_schema(self) -> None:
        self._run(_MYSQL_SCHEMA if self.backend == "mysql" else _SQLITE_SCHEMA)
        self.conn.commit()

    def seed_demo(self, count: int = 20, low: int = 100, high: int = 140) -> int:
        """Insert demo 'salaries' if the table is empty. Returns rows inserted."""
        if self._run("SELECT COUNT(*) FROM data_table").fetchone()[0]:
            return 0
        rng = random.SystemRandom()
        for _ in range(count):
            self._run("INSERT INTO data_table (number_data) VALUES (?)",
                      (rng.randint(low, high),))
        self.conn.commit()
        return count

    def plain_rows(self):
        return self._run("SELECT data_id, number_data FROM data_table ORDER BY data_id").fetchall()

    def encrypted_rows(self):
        return self._run(
            "SELECT data_id, number_data, encrypted_data, hash_sha256 "
            "FROM data_table ORDER BY data_id").fetchall()

    def save_ciphertext(self, data_id: int, blob: bytes, digest: str) -> None:
        self._run("UPDATE data_table SET encrypted_data = ?, hash_sha256 = ? WHERE data_id = ?",
                  (blob, digest, data_id))

    def commit(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
