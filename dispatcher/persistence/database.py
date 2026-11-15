import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum

import psycopg
from psycopg import pq, sql
from pydantic import SecretStr


class PostgresConnection:
    def __init__(self, connection: psycopg.Connection):
        self.connection = connection

    @property
    def in_transaction(self) -> bool:
        return self.connection.info.transaction_status == pq.TransactionStatus.INTRANS

    def execute(
        self, query: str | sql.Composable, parameters: tuple | None = None
    ) -> psycopg.Cursor:
        if isinstance(query, str) and parameters is not None:
            query = query.replace("?", "%s")
            parameters = tuple(
                str(value) if isinstance(value, StrEnum) else value for value in parameters
            )
        return self.connection.execute(query, parameters)

    def executescript(self, script: str) -> None:
        self.execute(script)

    def commit(self) -> None:
        self.connection.commit()


StoreConnection = sqlite3.Connection | PostgresConnection


@dataclass(frozen=True)
class PostgresDatabase:
    dsn: SecretStr
    password: SecretStr
    schema: str = "public"
    audit_role: str = ""

    @contextmanager
    def connect(self) -> Iterator[PostgresConnection]:
        if not re.fullmatch(r"[a-z_][a-z_0-9]{0,62}", self.schema):
            raise ValueError("Недопустимое имя схемы PostgreSQL.")
        with psycopg.connect(
            self.dsn.get_secret_value(),
            password=self.password.get_secret_value(),
            connect_timeout=3,
            options=(
                f"-c search_path={self.schema} -c timezone=UTC -c synchronous_commit=on "
                "-c lock_timeout=3000 -c statement_timeout=8000"
            ),
        ) as connection:
            yield PostgresConnection(connection)


def begin_write(db: StoreConnection) -> None:
    # Операции, использующие begin_write, сериализуются в пределах схемы:
    # проверка состояния и последующая запись не расходятся между запросами.
    if isinstance(db, PostgresConnection):
        db.execute(
            "SELECT pg_advisory_xact_lock(hashtext(current_database()), hashtext(current_schema()))"
        )
    else:
        db.execute("BEGIN IMMEDIATE")


def begin_read(db: StoreConnection) -> None:
    # Несколько чтений в одном разборе должны видеть согласованный снимок данных.
    if isinstance(db, PostgresConnection):
        db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
    else:
        db.execute("BEGIN")
