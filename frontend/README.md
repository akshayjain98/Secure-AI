# SecureAI Workspace — frontend

Next.js 16 (App Router, Cache Components) + TypeScript + Tailwind v4 + shadcn/ui (Base UI) +
TanStack Query. It covers every backend endpoint: auth, organizations, members, permission
overrides, projects, tasks, documents and the audit log.

## Run it

```bash
# 1. backend (repo root): migrations must be at head (0007), API on :8000
uv run alembic upgrade head
uv run uvicorn app.api.main:create_app --factory --port 8000

# 2. frontend
cd frontend
cp .env.example .env.local        # SECUREAI_API_ORIGIN, defaults to http://127.0.0.1:8000
npm install
npm run dev                       # http://localhost:5173
```

Port 5173 matches the backend's default `SECUREAI_PUBLIC_URL`, so the links the API "emails"
(`/verify-email#token=…`, `/reset-password#token=…`, `/invitations`) open this app. In
development the console mailer prints those links in the API's log.

| Script | |
|---|---|
| `npm run dev` | dev server on :5173 |
| `npm run build` / `npm start` | production build / serve on :5173 |
| `npm run lint` | ESLint (incl. React Compiler rules) |
| `npm run typecheck` | regenerate route types + `tsc --noEmit` |

## How it talks to the API

The browser only ever talks to this origin. `next.config.ts` proxies two prefixes:

| Browser path | Backend | Why |
|---|---|---|
| `/auth/*` | `{API}/auth/*` | The refresh cookie is `Path=/auth; SameSite=Strict; Secure; HttpOnly`. It must be served same-origin at exactly this path. |
| `/api/*` | `{API}/*` | Everything else (`/me`, `/orgs/…`). |

So no page may live under `/auth` or `/api`, and the backend needs no CORS.

## Session model (`src/lib/api/client.ts`, `src/lib/auth/session.tsx`)

- **Access token (JWT, 10 min): in memory only.** It is never written to localStorage,
  sessionStorage or a cookie. A page load gets a new one from `/auth/refresh`.
- **Refresh token: HttpOnly cookie.** JavaScript never sees it. Refresh and logout send the
  `X-SecureAI-CSRF: 1` header the backend requires.
- **Refreshes are serialized.** The backend uses single-use refresh tokens with reuse detection
  and no grace window, so two concurrent refreshes would look like a replay and revoke the whole
  session. Refreshes are single-flight within a tab and serialized across tabs with the Web Locks
  API (`navigator.locks`). This holds under React StrictMode and with several tabs open (both
  covered by the browser test).
- Requests refresh lazily when the token is about to expire, and retry once after a 401.
  Network/5xx/429 failures during bootstrap show an "offline" screen instead of signing you out.
- **Cross-tab sync** (`BroadcastChannel`): signing out in one tab signs out all tabs. All cached
  query data is cleared on any session change.

Because the session lives in browser memory, everything behind sign-in renders on the client.
The server sends prerendered static shells (auth pages are fully static). The `(app)` layout
sets `instant = false`, and `next.config.ts` sets
`experimental.instantInsights.validationLevel: "manual-warning"`, because navigation into the
signed-in area deliberately waits on that client-side session check.

## Authorization in the UI

The database (RLS) is the only authority. The UI uses `/me` with `X-Org-Id` to get the
caller's role and effective permissions, and only uses them to **hide controls the server would
refuse anyway** (`useOrg().can("task.delete")`). Every action still handles the server's answer:

- **403** → "Access restricted" state, or the server's own rule message in a toast
  (e.g. *"An organization must keep at least one active administrator"*).
- **404** → "Not found". The backend uses 404 for rows you can't see, so hidden IDs aren't confirmed.
- **422** → mapped onto the form field when the API names one.

UI hints mirror the backend rules where they are known: role assignment is limited to your
rank, there are no actions on your own membership row, only the owner can change task
visibility or edit/delete a document, and a document with `project` visibility must be
attached to a project.

## Other security details

- Strict response headers on every page: CSP (`frame-ancestors 'none'`, `connect-src 'self'`,
  `object-src 'none'`), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `nosniff`,
  COOP. The CSP is static (no nonces), so `script-src` needs `'unsafe-inline'` for Next's inline
  bootstrap. Moving to nonces would force every route to dynamic rendering.
- Email tokens arrive in the URL **fragment** and are removed from the address bar and history
  as soon as they are read (`use-fragment-token.ts`).
- `?next=` after login only accepts same-site relative paths (`safeNext`), which blocks open
  redirects. A deliberate sign-out never carries `next`, so the next person to sign in on that
  browser doesn't land on the previous user's page.
- Organization ids from the URL are validated as UUIDs before they are sent anywhere. Unknown
  orgs, other tenants' orgs and suspended memberships all show the same "No access" screen,
  matching the backend's indistinguishable 403.
- Documents: file storage is a later backend phase. The app computes size and SHA-256 locally
  with Web Crypto, and the file bytes never leave the browser.

## Production deployment note: client IPs

Next's rewrite proxy does **not** add `X-Forwarded-For` (verified). Behind it, the API sees
every user as `127.0.0.1`. Per-IP rate limits then become one global bucket, and audit-log IPs
are all the same. In production, route `/auth` and `/api` at your edge proxy (Caddy, Nginx, a
load balancer) **directly to uvicorn**, set `X-Forwarded-For` there, and run uvicorn with
`--forwarded-allow-ips=<proxy address>`. Keep the same paths (strip `/api`) so the browser still
sees one origin and the cookie path stays `/auth`. Let Next serve only the pages.

## Layout

```
src/
  app/
    (auth)/           login, register, verify-email, forgot-password, reset-password (static)
    (app)/            signed-in area behind <AuthGate>: /, /orgs, /invitations, /account
      orgs/[orgId]/   <OrgGate> binds the org: overview, projects/[projectId], tasks,
                      documents, members, audit, settings
  components/
    app-shell/        sidebar, org switcher, user menu, auth gate, theme toggle
    auth/ org/ projects/ tasks/ documents/ members/ audit/ overview/
    common/           page header, empty/error/loading states, confirm dialog, badges, select
    ui/               shadcn/ui (Base UI) primitives
  lib/
    api/              client (tokens, refresh, errors), typed endpoints, response types
    auth/session.tsx  AuthProvider: bootstrap, login/logout, cross-tab sync
    org-context.tsx   current org, role, permissions, can(), user directory
    queries.ts        TanStack Query keys (always org-scoped) and hooks
```
