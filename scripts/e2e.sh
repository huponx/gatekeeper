#!/usr/bin/env bash
# Local end to end run of the BFF against a real identity (sibling checkout ../identity):
# web app (cross origin, cookie, CORS, CSRF), mobile (PKCE + Bearer), service (client credentials + Bearer).
# The routes reach identity over gRPC with a token exchanged for its audience.
#
# Needs Postgres with the identity schema (db-migration V1..V8) and Redis: POSTGRES_* / REDIS_*.
# identity-setup (sibling checkout) creates the admin when none exists, with the password below, and the clients.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'kill ${ipid:-0} ${gpid:-0} 2>/dev/null || true; rm -rf "$tmp"' EXIT

ID_HTTP=${ID_HTTP:-18080}; ID_GRPC=${ID_GRPC:-19090}; GK_PORT=${GK_PORT:-18081}
export ENV=local
openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/k1.pem" 2>/dev/null
(cd ../identity && go build -o "$tmp/identity" ./cmd/identity && go build -o "$tmp/identity-setup" ./cmd/identity-setup)
go build -o "$tmp/gatekeeper" ./cmd/gatekeeper

export IDENTITY_SIGNING_KEY_FILE=$tmp/k1.pem IDENTITY_SIGNING_KEY_ID=k1 IDENTITY_MFA_KEY="k1:$(openssl rand -base64 32)"
export IDENTITY_ISSUER=http://localhost:$ID_HTTP
export SETUP_ADMIN_PASSWORD='Correct-Horse-Battery-9'

suf=$(openssl rand -hex 3); client=gk-$suf
ui=http://localhost:13000   # a web app on another origin than the gateway
mobile=mobile-$suf; mobile_redirect=com.example.app:/callback; svc=svc-$suf
secret=$(openssl rand -hex 16); svc_secret=$(openssl rand -hex 16)
# keep_password: the e2e signs in with the given password (a real setup forces a change).
# The setup runs twice: it is idempotent (the second run only finds everything in place).
# gatekeeper: web app on another origin (post logout URI); mobile: public client; service: client credentials
# with the admin role (the gateway forwards its permissions).
SETUP_CONFIG=$(cat <<EOF
{"admin":{"email":"admin@example.com","keep_password":true},
 "clients":[
  {"id":"$client","type":"confidential","resource":"gatekeeper","secret_env":"E2E_GK_SECRET",
   "redirect_uris":["http://localhost:$GK_PORT/auth/callback"],"post_logout_uris":["$ui/"],
   "grants":["authorization_code","refresh_token","client_credentials","urn:ietf:params:oauth:grant-type:token-exchange"]},
  {"id":"$mobile","type":"public","resource":"gatekeeper","redirect_uris":["$mobile_redirect"]},
  {"id":"$svc","type":"confidential","resource":"gatekeeper","secret_env":"E2E_SVC_SECRET","grants":["client_credentials"],"roles":["admin"]}],
 "exchange_policies":[{"client":"$client","audience":"identity","max_depth":1},{"client":"$svc","audience":"gatekeeper","max_depth":1}]}
EOF
)
export SETUP_CONFIG E2E_GK_SECRET=$secret E2E_SVC_SECRET=$svc_secret
"$tmp/identity-setup" && "$tmp/identity-setup"

HTTP_PORT=$ID_HTTP PORT=$ID_GRPC "$tmp/identity" >"$tmp/identity.log" 2>&1 & ipid=$!
for _ in $(seq 1 50); do curl -fs "$IDENTITY_ISSUER/healthz" >/dev/null && break; sleep 0.2; done

cat >"$tmp/routes.yaml" <<EOF
upstreams:
  identity: {target: "localhost:$ID_GRPC"}
routes:
  - {http: GET /api/roles, grpc: identity.v1.IdentityService/ListRoles, upstream: identity, permission: "identity:role:read"}
  - {http: POST /api/roles, grpc: identity.v1.IdentityService/CreateRole, upstream: identity, permission: "identity:role:write"}
EOF

PORT=$GK_PORT GATEKEEPER_PUBLIC_URL=http://localhost:$GK_PORT GATEKEEPER_ROUTES_FILE=$tmp/routes.yaml \
GATEKEEPER_IDENTITY_ISSUER=$IDENTITY_ISSUER GATEKEEPER_CLIENT_ID=$client GATEKEEPER_CLIENT_SECRET=$secret GATEKEEPER_AUDIENCE=gatekeeper \
GATEKEEPER_SESSION_KEY="k1:$(openssl rand -base64 32)" GATEKEEPER_UI_ORIGINS=$ui \
  "$tmp/gatekeeper" >"$tmp/gatekeeper.log" 2>&1 & gpid=$!
for _ in $(seq 1 50); do curl -fs "http://localhost:$GK_PORT/healthz" >/dev/null && break; sleep 0.2; done

GK=http://localhost:$GK_PORT ISSUER=$IDENTITY_ISSUER EMAIL=admin@example.com PASSWORD=$SETUP_ADMIN_PASSWORD \
UI_ORIGIN=$ui MOBILE_CLIENT=$mobile MOBILE_REDIRECT=$mobile_redirect SERVICE_CLIENT=$svc SERVICE_SECRET=$svc_secret \
  python3 scripts/e2e.py || { echo '--- gatekeeper log'; tail -20 "$tmp/gatekeeper.log"; echo '--- identity log'; tail -20 "$tmp/identity.log"; exit 1; }
