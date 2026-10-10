# Enterprise frontend security

The browser client uses the existing bearer session API and keeps the token
session-scoped. It never logs credentials, passwords, authorization headers, or
raw evidence, and it does not render API HTML. Organization changes replace
tenant-scoped requests rather than merging cached state. UI visibility is only a
hint; backend OrganizationContext and RBAC remain authoritative. 401 returns to
login, 403 is shown as permission denied, and 429 displays bounded retry
feedback. Production deployment must use explicit API origins/CORS and HTTPS.
