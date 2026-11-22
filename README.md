# gatekeeper

The shared HTTP gateway (`api.example.com`) in front of the gRPC services. It turns JSON requests into gRPC calls with a token **exchanged for the audience of each upstream**. Three kinds of callers use the same routes:

| Caller | Authenticates with | Notes |
| --- | --- | --- |
| Web apps (`dict.example.com`, `bill.example.com`, ...) | `HttpOnly` session cookie of the gateway (BFF: tokens stay in Redis, the browser never sees one) | cross origin calls: CORS for `GATEKEEPER_UI_ORIGINS`, `Origin` + `Csrf-Token` on unsafe methods; one login for all web apps |
| Mobile apps | `Authorization: Bearer <access token>` | own public client (PKCE through the system browser); the app stores and refreshes its tokens |
| Services (machine to machine) | `Authorization: Bearer <access token>` | `client_credentials` for the audience `gatekeeper` |

```
dict.example.com  --cookie, CORS-->  gatekeeper (api.example.com) --token exchange--> identity
bill.example.com  --cookie, CORS-->        |  JSON -> gRPC, Bearer (aud = upstream)
mobile / service  --Bearer-------->        +--------------------------> courier / other gRPC services
```

The cookie is set on `api.example.com` and is sent to it from `dict.` and `bill.` because they are the same site (`example.com`): the web apps must share the registrable domain, otherwise browsers block the cookie.

Module: `github.com/huponx/gatekeeper`. Shared code (`oidcclient`, `tokenexchange`, `jwtx`, `authn`, `httpx`) comes from `gocommon`. One release per environment.

How and why the gateway acts as a BFF (sessions, cookie, CORS, CSRF, logout, limits): [docs/bff.md](docs/bff.md). A request walk through: [identity/docs/api-call-flow.md](../identity/docs/api-call-flow.md).

## Endpoints

| Endpoint | |
| --- | --- |
| `GET /auth/login?return_to=https://dict.example.com/app` | Starts the login (redirect to identity). `return_to` is a path of this host or a URL on one of `GATEKEEPER_UI_ORIGINS`; anything else falls back to `GATEKEEPER_POST_LOGIN_URL` |
| `GET /auth/callback` | Identity returns here; checks `state` against the browser cookie, exchanges the code, creates the session |
| `GET /auth/me` | `sub`, roles, scopes, permissions and the `csrf_token` of the session (never a token) |
| `POST /auth/logout?return_to=https://dict.example.com/` | Ends the session, revokes the refresh token, returns `logout_url` (end-session of identity; it sends the browser back to `return_to`, a UI origin registered as a post logout URI of the client) |
| `POST /auth/backchannel-logout` | Called by identity: deletes the sessions of the logged-out user/session |
| routes of `routes.yaml` | JSON to gRPC, below |
| `/healthz`, `/readyz` | Probes (`readyz` checks Redis) |

### Web apps (cookie)

- CORS: for an `Origin` listed in `GATEKEEPER_UI_ORIGINS` the gateway answers with `Access-Control-Allow-Origin: <that origin>` and `Access-Control-Allow-Credentials: true` (never `*`), and answers preflights (`OPTIONS`) itself. Other origins get no CORS headers, so browsers block them. The web app calls with `fetch(url, {credentials: "include"})`.
- Unsafe methods (everything but `GET`) need the header `Origin` (one of `GATEKEEPER_UI_ORIGINS`) **and** `Csrf-Token: <csrf_token from /auth/me>`.
- Cookie: `__Host-session` (`Secure`, `HttpOnly`, `SameSite=Lax`, path `/`, no `Domain`) on the gateway host; a new session id at every login. The session is shared by all web apps: keep their CSP strict and the permissions of users minimal, since script injection in one web app can call the API as the user.
- Flow of a web app: `GET /auth/me`; on `401` navigate to `/auth/login?return_to=<own URL>`; after the redirect back call `/auth/me` again.

### Mobile apps and services (Bearer)

- Any request with an `Authorization` header is handled as Bearer: the token is verified locally (signature, issuer, `aud` = `GATEKEEPER_AUDIENCE`, expiry); a bad or missing token is a `401` with `WWW-Authenticate`, never a fallback to the cookie. The Origin and CSRF checks do not apply (there is no cookie to abuse). Permissions, token exchange and routes are the same as for web apps.
- No session on the gateway: the client refreshes its own tokens at identity. A revoked token stays valid until it expires, so keep the access token lifetime short.
- Mobile: register a public client with `--resource gatekeeper` and the app's redirect URI (custom scheme or app link), run authorization code + PKCE (S256) in the system browser (RFC 8252), keep the refresh token in Keychain/Keystore.
- Service: register a confidential client with `--grant client_credentials` and a role, add an exchange policy for the audience `gatekeeper`, request `grant_type=client_credentials&audience=gatekeeper`. For the upstream call identity exchanges the service token too (subject stays the service, `act` = gatekeeper, permissions of the service's roles on the upstream audience).

## Routes

```yaml
descriptors: /etc/gatekeeper/descriptors.binpb   # optional; without it gatekeeper uses gRPC reflection
upstreams:
  courier: {target: courier.application.svc:9090}
routes:
  - http: POST /api/notifications
    grpc: courier.v1.CourierService/SendNotification
    upstream: courier
    audience: courier                  # aud of the exchanged token (default: the upstream name)
    permission: courier:notification:send
  - {http: GET /api/me/prefs/{id}, grpc: prefs.v1.Prefs/Get, upstream: prefs, public: true}
```

- **Deny by default**: a route needs `permission` (checked against the `perms` of the user's token) or `public: true` (any signed-in user, never anonymous). Anonymous callers only reach `/auth/*`.
- The gRPC request is the JSON body (an object, `Content-Type: application/json`, 1 MiB max) plus the query string and the `{path}` parameters, which fill top level fields (path parameters win). Unknown fields are a `400`.
- Unary methods only. gRPC status codes map to HTTP (`NotFound` 404, `InvalidArgument` 400, `PermissionDenied` 403, `Unavailable` 503, ...); messages of 5xx are replaced by a generic text.
- `descriptors.binpb` (`make descriptors`, which runs `buf build ../protos --path ../protos/identity -o descriptors.binpb`) is the production source and is committed: the chart ships it in the ConfigMap, routes are checked at start-up and the upstreams keep reflection off (identity does not serve it, without the file the gateway fails with `Unimplemented ... ServerReflection`). After a change in `protos` run `make descriptors` and commit the file; `go test ./internal/proxy` fails when it is stale. Reflection works for local runs and for upstreams that enable it; gatekeeper authenticates those calls with its own client-credentials token.
- Every upstream call carries a token from RFC 8693 token exchange (`aud` = route audience, `sub` = the user, `act` = this client, 2 minutes, no refresh), so each service sees only a token meant for it. Identity must have an exchange policy `(client, audience)` for every audience used.

## Configuration

| Variable | Default | |
| --- | --- | --- |
| `GATEKEEPER_PUBLIC_URL` | required | `https://api.example.com`; `+/auth/callback` is the redirect URI to register |
| `GATEKEEPER_UI_ORIGINS` | the public URL | web apps allowed to call from a browser, separated by commas, spaces or new lines (`https://dict.example.com,https://bill.example.com`, or one origin per line in a YAML block scalar `|-`): CORS, `return_to` targets, accepted `Origin` of unsafe requests. Must be `https` outside `ENV=local` |
| `GATEKEEPER_IDENTITY_ISSUER` | required | issuer URL of identity |
| `GATEKEEPER_CLIENT_ID` / `GATEKEEPER_CLIENT_SECRET` | required | the confidential client of the gateway (secret from a Secret created by mm-ansible) |
| `GATEKEEPER_AUDIENCE` | required | the `resource` of that client (`gatekeeper`): `aud` of the user tokens it holds and of the Bearer tokens it accepts |
| `GATEKEEPER_SESSION_KEY` | required | `id:base64(32 bytes)`, comma separated, the first seals tokens in Redis (AES-GCM), the others only open (rotation) |
| `GATEKEEPER_ROUTES_FILE` | `/etc/gatekeeper/routes.yaml` | |
| `GATEKEEPER_ALLOWED_ORIGINS` | empty | former name of `GATEKEEPER_UI_ORIGINS`, merged with it |
| `GATEKEEPER_SESSION_IDLE_TTL` / `_ABSOLUTE_TTL` | `8h` / `168h` | sliding and hard lifetime |
| `GATEKEEPER_ACR_VALUES` | empty | for example `mfa` to require a second factor on every login |
| `GATEKEEPER_UPSTREAM_INSECURE` | `true` | plain gRPC to upstreams in the cluster |
| `GATEKEEPER_POST_LOGIN_URL` | `/` | |
| `REDIS_*`, `PORT` (8080), `ENV`, `LOG_*` | | gocommon blocks |

## Setup (one time per environment)

1. The gateway client (confidential, `resource` = `gatekeeper`) and its exchange policy (audience `identity`, the only upstream of `routes.yaml`) are created by the identity setup Job (identity README, "Initial setup Job"): the `setup.job.container.env` `SETUP_CONFIG` of `mm-deploy` `applications/<env>/identity.yaml` lists the redirect URI `https://api.<env host>/auth/callback`, the post logout URIs of the web apps, the back-channel logout URI `http://gatekeeper.application.svc/auth/backchannel-logout` and the grants `authorization_code`, `refresh_token`, `client_credentials`, `urn:ietf:params:oauth:grant-type:token-exchange`. The client secret is the Secret `gatekeeper-client` (generated by `make identity-secrets`, nothing is printed).
2. Secrets: created by `mm-ansible` (`k8s_secrets`, values in its vault, see its README, "Identity and gatekeeper secrets"): client secret (`gatekeeper-client`, also read by the identity setup Job), session key (`gatekeeper-session`, `k1:<base64 32 bytes>`, generated by `make identity-secrets`), Redis password. Then `make deploy TAGS=secrets`.
3. Routes: nothing to ship. The chart packages `routes.yaml` and `descriptors.binpb` (root of this repo, linked from `charts/gatekeeper/files/`) and renders them into the ConfigMap `gatekeeper-routes` (upstream addresses: values `routes.upstreams`). To add or change a route edit that file (and run `make descriptors` when it uses a new method), merge, release gatekeeper and merge the deployment PR of `mm-deploy`; ArgoCD applies the ConfigMap and Reloader restarts the pods. `make routes` writes `routes.local.yaml` for local runs.
4. `applications/<env>/gatekeeper.yaml` in `mm-deploy`: host `api.<env host>`, `GATEKEEPER_UI_ORIGINS` and the secrets.

### Adding a web app

Add its origin to `GATEKEEPER_UI_ORIGINS` (mm-deploy) and its URL as a post logout URI of the `gatekeeper` client. identity has no update call for clients, so add the URL to `post_logout_uris` in `SETUP_CONFIG` (put the `setup:` block of the identity Application back, sync, remove it again; the Job only adds URIs). It must share the registrable domain with the gateway.

### Adding a mobile app

Create a public client in the admin app (Clients, `resource` = `gatekeeper`, redirect URI `com.example.app:/callback`; the grants `authorization_code` and `refresh_token`). The redirect URI is a private-use scheme in reverse domain form (`com.example.app:/callback`) or an https app link.

### Adding a service that calls the gateway

Create a confidential client in the admin app (`resource` = `gatekeeper`, grant `client_credentials`), give it a role (Roles, assign to the client) and add an exchange policy `client -> gatekeeper` (Exchange policies). The role decides what the service may do: the gateway checks the route `permission` against it and identity issues the upstream token with the same permissions.

## Images and charts

One image (distroless, non-root) is built from the repository root: `make docker IMAGE_TAG=dev` gives `ghcr.io/huponx/gatekeeper:dev` (`build/gatekeeper/Dockerfile`). The chart `charts/gatekeeper` wraps the `go-application` chart (dependency alias `application`, values under `application:`). `version`, `appVersion` and `image.tag` are written at release time by the CI; the committed values only keep `helm template` working. Secret values never go in git: set `application.secrets` with `secretName`/`key` in `mm-deploy`.

## CI/CD

`.github/config/ci.yaml` is the contract and `.github/workflows/{pr,main,staging,production}.yml` call the reusable workflows of `huponx/actions` (`service-*.yml`):

| Flow | Trigger | Result |
|---|---|---|
| pr | pull request to `main` | lint, test, build, Trivy scan, `helm lint`; nothing pushed |
| main | push to `main` | image and chart pushed (`1.YYYYMMDD.<run>-main-<sha7>`), deployment PR for `dev` in `mm-deploy` |
| staging | push to `release*` | pre-release `v<YYYY>.<MM>.N-release-<sha7>`, image and chart pushed, deployment PR for `staging` |
| production | release published | no build; verifies the image and chart of the release tag exist, deployment PR for `production` |

Required secret: `BOT_TOKEN` (write access to `mm-deploy`). `staging` and `production` are `enabled: false` in `ci.yaml` until their ArgoCD and `applications/<env>` exist.

## Setup (one time, GitHub)

Commands use the [GitHub CLI](https://cli.github.com) (`gh auth login` first, with admin rights on the repositories). Do this once per repository, before the per environment setup above.

1. **`huponx/actions`** must be published: a release exists and the floating `v1` tag points to it. A private repo must share it with the other repositories of the owner:

   ```bash
   gh release list -R huponx/actions --limit 3
   gh api repos/huponx/actions/git/ref/tags/v1 --jq .object.sha
   gh api -X PUT repos/huponx/actions/actions/permissions/access -f access_level=user   # private repo only
   ```

2. **Token for `mm-deploy`** (`GITHUB_TOKEN` cannot open PRs in another repository). A fine-grained PAT (repository `huponx/mm-deploy`: Contents and Pull requests write), or a GitHub App installed on `mm-deploy` (the App wins when `DEPLOY_APP_ID` is set):

   ```bash
   gh secret set BOT_TOKEN -R huponx/gatekeeper                    # paste the token
   # or
   gh variable set DEPLOY_APP_ID -R huponx/gatekeeper --body "<app id>"
   gh secret set DEPLOY_APP_PRIVATE_KEY -R huponx/gatekeeper < app-private-key.pem
   ```

   Optional: `gh secret set SLACK_WEBHOOK_URL -R huponx/gatekeeper` (and `slack-channel` in `ci.yaml`) for deployment PR notifications.

3. **Workflow permissions** (packages and the staging pre-release need write):

   ```bash
   gh api -X PUT repos/huponx/gatekeeper/actions/permissions/workflow \
     -f default_workflow_permissions=write -F can_approve_pull_request_reviews=false
   ```

4. **GHCR packages**: after the first `main` run the packages `gatekeeper` and `charts/gatekeeper` exist. Link each to the repository (package settings, "Manage Actions access", role Write) and give the ArgoCD clusters pull access (public, or an image pull secret and an OCI repository credential in each ArgoCD). `go-application` must be readable from `oci://ghcr.io/huponx/charts`.

5. **Branch ruleset** for `main` (PR required, squash only, required checks of the `pr` flow, no force push or deletion). Merge the workflows to `main` first, while it is unprotected: status checks only show in the ruleset picker after they have run once. Save as `main-ruleset.json` (input only, do not commit):

   ```json
   {
     "name": "protect main",
     "target": "branch",
     "enforcement": "active",
     "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
     "rules": [
       { "type": "deletion" },
       { "type": "non_fast_forward" },
       { "type": "pull_request", "parameters": {
           "required_approving_review_count": 0, "dismiss_stale_reviews_on_push": false,
           "require_code_owner_review": false, "require_last_push_approval": false,
           "required_review_thread_resolution": false,
           "allowed_merge_methods": ["squash"] } },
       { "type": "required_status_checks", "parameters": {
           "strict_required_status_checks_policy": true,
           "required_status_checks": [
             { "context": "pr / contract" },
             { "context": "pr / lint-test" },
             { "context": "pr / build / build (gatekeeper)" } ] } }
     ],
     "bypass_actors": []
   }
   ```

   ```bash
   REPO=huponx/gatekeeper
   gh api repos/$REPO/rulesets --method POST --input main-ruleset.json
   gh api repos/$REPO/rulesets --jq '.[] | {id, name, enforcement}'   # verify
   ```

   Confirm the check names with `gh pr checks <pr>` after the first PR run. To change it later: `gh api repos/$REPO/rulesets/<id> --method PUT --input main-ruleset.json`. Rulesets on a private repo need a paid GitHub plan.

   Second ruleset for `release*`: a merge into it creates a staging pre-release, so it needs a PR with the same checks as `main` (the `pr` flow also runs on PRs into `release*`), and no force push or deletion. Save as `release-ruleset.json` and apply the same way:

   ```json
   {
     "name": "protect release branches",
     "target": "branch",
     "enforcement": "active",
     "conditions": { "ref_name": { "include": ["refs/heads/release*"], "exclude": [] } },
     "rules": [
       { "type": "deletion" },
       { "type": "non_fast_forward" },
       { "type": "pull_request", "parameters": {
           "required_approving_review_count": 0, "dismiss_stale_reviews_on_push": false,
           "require_code_owner_review": false, "require_last_push_approval": false,
           "required_review_thread_resolution": false,
           "allowed_merge_methods": ["merge", "squash"] } },
       { "type": "required_status_checks", "parameters": {
           "strict_required_status_checks_policy": false,
           "required_status_checks": [
             { "context": "pr / contract" },
             { "context": "pr / lint-test" },
             { "context": "pr / build / build (gatekeeper)" } ] } }
     ],
     "bypass_actors": []
   }
   ```

   ```bash
   gh api repos/$REPO/rulesets --method POST --input release-ruleset.json
   gh api repos/$REPO/rulesets --jq '.[] | {id, name}'   # id for a later PUT
   ```

   The ruleset applies to every `release*` branch, so create the first one (for example `release`) from `main` before applying it, or push it while the ruleset is not yet active.

6. **`mm-deploy`**: auto merge and the label (once for all services):

   ```bash
   gh repo edit huponx/mm-deploy --enable-auto-merge --delete-branch-on-merge
   gh label create automerge -R huponx/mm-deploy --color 0E8A16 --description "Merge automatically when checks pass" || true
   ```

   After the first publish, `applications/<env>/gatekeeper.yaml` gets `targetRevision` set to the published version; later versions come from the deployment PRs.

7. **Verify**:

   ```bash
   gh secret list -R huponx/gatekeeper && gh variable list -R huponx/gatekeeper
   gh run list -R huponx/gatekeeper --workflow main.yml --limit 1     # after a merge into main
   gh pr list -R huponx/mm-deploy --label automerge                   # the dev deployment PR
   ```

## Local development and tests

```bash
go test -race ./...                                  # routes, proxy (bufconn + reflection), sessions
GATEKEEPER_TEST_REDIS=localhost:6379 go test ./...   # also the Redis session tests
POSTGRES_PASSWORD=pw REDIS_HOST=localhost scripts/e2e.sh   # real identity: web app (CORS, cookie, CSRF, logout), mobile (PKCE + Bearer), service (client credentials + Bearer)
```

`scripts/e2e.sh` needs the `identity` repo next to this one, Postgres with the identity schema (db-migration `V1..V8`), Redis, and the sibling `identity` checkout (the script runs its `identity-setup`, which creates the admin and the clients).

Local `go.work` (git-ignored) points at `../gocommon`; after gocommon is released run `go get github.com/huponx/gocommon@latest && go mod tidy`.
