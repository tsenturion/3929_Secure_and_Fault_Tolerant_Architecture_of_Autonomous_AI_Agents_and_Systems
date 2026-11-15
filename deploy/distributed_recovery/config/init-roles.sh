#!/bin/sh
(
    set -eu
    psql --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
\getenv writer_password DISPATCHER_DB_PASSWORD
\getenv audit_password AUDIT_DB_PASSWORD
CREATE ROLE dispatcher_writer LOGIN PASSWORD :'writer_password';
CREATE ROLE dispatcher_audit LOGIN PASSWORD :'audit_password';
GRANT CREATE ON DATABASE dispatcher TO dispatcher_writer;
GRANT USAGE, CREATE ON SCHEMA public TO dispatcher_writer;
GRANT USAGE ON SCHEMA public TO dispatcher_audit;
SQL
)
