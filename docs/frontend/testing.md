# Frontend verification

From `frontend/`, run `npm install` then `npm run build`; this performs the
TypeScript check and production Vite build. Run the backend with the documented
Python 3.11 command and verify login, organization switching, Command Center,
Fleet, endpoint detail, and Compliance against real APIs. Empty states are
expected when the authenticated tenant has no data or a capability lacks a
backend route. The Python regression suite remains `python -m pytest -q`.
