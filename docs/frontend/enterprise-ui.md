# Enterprise Command Center

The browser UI in `frontend/` is a React + TypeScript + Vite presentation
layer over the existing tenant-aware Raven-X APIs. It provides a dark SOC shell,
real login/session handling, organization switching, command palette, Command
Center, Fleet/endpoint detail, and Compliance views. Empty/error states are honest when an API
does not expose a capability; no production fixtures are embedded.

Run `npm install && npm run dev` for development or `npm run build` for a static
production bundle. Vite proxies `/api`, `/health`, and `/ready` to the local
control plane at port 8000. Session tokens are session-scoped, tenant changes
reload data, and the backend remains authoritative for authorization.
