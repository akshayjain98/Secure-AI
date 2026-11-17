#!/bin/bash
# ---------------------------------------------------------------------------
# SecureAI Workspace - cluster bootstrap (runs ONCE, as the postgres superuser)
#
# This is the only step that needs superuser. Everything after it (Alembic
# migrations, seed data, the running application) uses least-privilege roles.
#
# Role model:
#   secureai_owner        NOLOGIN. Owns schemas/tables. Subject to RLS because
#                         every table uses FORCE ROW LEVEL SECURITY.
#   secureai_rls_definer  NOLOGIN, BYPASSRLS. Owns the SECURITY DEFINER helper
#                         functions that RLS policies call. Holds SELECT only on
#                         the authorization tables it must read. Cannot log in,
#                         cannot write anything.
#   secureai_migrator     LOGIN, BYPASSRLS. Used by Alembic and by ops/seed
#                         scripts. NEVER used by the running application.
#   secureai_app          LOGIN, NOBYPASSRLS, NOINHERIT, owns nothing, member of
#                         nothing. The only credential the API server holds.
# ---------------------------------------------------------------------------
set -euo pipefail

: "${SECUREAI_MIGRATOR_PASSWORD:?SECUREAI_MIGRATOR_PASSWORD is required}"
: "${SECUREAI_APP_PASSWORD:?SECUREAI_APP_PASSWORD is required}"
: "${SECUREAI_DATABASES:?SECUREAI_DATABASES is required}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
     -v migrator_pw="$SECUREAI_MIGRATOR_PASSWORD" \
     -v app_pw="$SECUREAI_APP_PASSWORD" <<'EOSQL'
CREATE ROLE secureai_owner       NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE secureai_rls_definer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS;
CREATE ROLE secureai_migrator    LOGIN   NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS
       PASSWORD :'migrator_pw';
CREATE ROLE secureai_app         LOGIN   NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT
       CONNECTION LIMIT 100 PASSWORD :'app_pw';

-- The migrator acts as the owner for DDL (SET ROLE secureai_owner) and may
-- SET ROLE to the definer role to create helper functions owned by it.
GRANT secureai_owner       TO secureai_migrator;
GRANT secureai_rls_definer TO secureai_migrator;

-- Defensive session defaults for the application role.
ALTER ROLE secureai_app SET statement_timeout = '15s';
ALTER ROLE secureai_app SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE secureai_app SET search_path = pg_catalog;
EOSQL

for db in $SECUREAI_DATABASES; do
  echo "bootstrapping database: $db"
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
       -v db="$db" <<'EOSQL'
CREATE DATABASE :"db" OWNER secureai_owner;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"db" TO secureai_app, secureai_migrator;
GRANT CREATE ON DATABASE :"db" TO secureai_owner;
EOSQL

  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$db" <<'EOSQL'
-- Nobody gets to create objects in public (default since PG15, made explicit).
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- Functions are EXECUTE-able by PUBLIC by default. Turn that off for every
-- function our roles will ever create. (Per-schema default privileges cannot
-- revoke a global default, so this must be done without IN SCHEMA.)
ALTER DEFAULT PRIVILEGES FOR ROLE secureai_owner       REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE secureai_rls_definer REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- Alembic bookkeeping lives in its own schema, owned by the owner role.
CREATE SCHEMA secureai_migrations AUTHORIZATION secureai_owner;
EOSQL
done
