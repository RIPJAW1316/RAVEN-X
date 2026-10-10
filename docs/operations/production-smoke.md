# Production smoke checks

From the deployment host, verify `GET /health` returns liveness and `GET
/ready` returns core readiness. Confirm the expected auth, organization,
assessment, compliance, and agent routes are mounted, then inspect safe logs
and metrics for startup/worker errors. Do not embed credentials in this
procedure.
