#!/usr/bin/env bash
# One-time superuser step for databases bootstrapped BEFORE Phase 2.
#
# Fresh volumes get this role from docker/postgres/init/00-bootstrap.sh. An
# existing volume needs it created once, because secureai_migrator is
# NOCREATEROLE and so migration 0004 cannot create it itself.
#
#   docker exec -i secureai-postgres bash < docker/postgres/upgrades/0004_auth_definer_role.sh
#
# Idempotent: safe to run more than once.
set -euo pipefail

: "${SECUREAI_DATABASES:?SECUREAI_DATABASES is required}"

psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-postgres}" --dbname postgres <<'EOSQL'
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'secureai_auth_definer') THEN
        CREATE ROLE secureai_auth_definer
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS;
    END IF;
END $$;
GRANT secureai_auth_definer TO secureai_migrator;
EOSQL

for db in $SECUREAI_DATABASES; do
  psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-postgres}" --dbname "$db" <<'EOSQL'
ALTER DEFAULT PRIVILEGES FOR ROLE secureai_auth_definer REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
EOSQL
done
echo "secureai_auth_definer ready"
