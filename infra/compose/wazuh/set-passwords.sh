#!/usr/bin/env bash
# Replaces the well-known Wazuh demo passwords (SecretPassword / kibanaserver /
# MyS3cr37P450r.*-) with real ones from .env, BEFORE the stack's first boot.
# Must run after generate-indexer-certs.yml and before `docker compose up`.
set -euo pipefail
cd "$(dirname "$0")"

set -a
source .env
set +a

WAZUH_INDEXER_IMAGE="wazuh/wazuh-indexer:4.14.7"
HASH_TOOL="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh"

hash_password() {
  docker run --rm "$WAZUH_INDEXER_IMAGE" bash "$HASH_TOOL" -p "$1" | tail -1
}

ADMIN_HASH=$(hash_password "$INDEXER_PASSWORD")
KIBANA_HASH=$(hash_password "$DASHBOARD_PASSWORD")

python3 - "$ADMIN_HASH" "$KIBANA_HASH" <<'PYEOF'
import sys
path = "config/wazuh_indexer/internal_users.yml"
old_admin = "$2y$12$K/SpwjtB.wOHJ/Nc6GVRDuc1h0rM1DfvziFRNPtk27P.c4yDr9njO"
old_kibana = "$2a$12$4AcgAt3xwOWadA5s5blL6ev39OXDNhmOesEoo33eZtrq2N0YrU3H."
new_admin, new_kibana = sys.argv[1], sys.argv[2]
content = open(path).read()
assert old_admin in content, "admin hash not found - already replaced?"
assert old_kibana in content, "kibanaserver hash not found - already replaced?"
content = content.replace(old_admin, new_admin).replace(old_kibana, new_kibana)
open(path, "w").write(content)
print("internal_users.yml updated")
PYEOF

python3 - "$INDEXER_PASSWORD" "$DASHBOARD_PASSWORD" "$API_PASSWORD" <<'PYEOF'
import sys
indexer_pw, dashboard_pw, api_pw = sys.argv[1], sys.argv[2], sys.argv[3]

compose_path = "docker-compose.yml"
content = open(compose_path).read()
content = content.replace("INDEXER_PASSWORD=SecretPassword", f"INDEXER_PASSWORD={indexer_pw}")
content = content.replace("API_PASSWORD=MyS3cr37P450r.*-", f"API_PASSWORD={api_pw}")
content = content.replace("DASHBOARD_PASSWORD=kibanaserver", f"DASHBOARD_PASSWORD={dashboard_pw}")
open(compose_path, "w").write(content)

wazuh_yml_path = "config/wazuh_dashboard/wazuh.yml"
content2 = open(wazuh_yml_path).read()
content2 = content2.replace('password: "MyS3cr37P450r.*-"', f'password: "{api_pw}"')
open(wazuh_yml_path, "w").write(content2)
print("docker-compose.yml and wazuh.yml updated")
PYEOF

echo "Done. Now run: docker compose -f generate-indexer-certs.yml run --rm generator && docker compose up -d"
