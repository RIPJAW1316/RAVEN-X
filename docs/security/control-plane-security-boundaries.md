# Control-plane security boundaries

## MITIGATED

- Authentication, authorization, and audit are separate concepts.
- Endpoint principals are self-scoped and cannot submit messages for another endpoint.
- Unknown actions and unconfigured principal actions are denied.
- Agent replay, direction, freshness, credential, and endpoint-binding checks remain
  in the existing message pipeline.
- Audit records are append-only through the application repository and recursively
  redact sensitive metadata.

## PARTIAL

- `SYSTEM` is intentionally powerful for current internal lifecycle workflows; its
  permitted action set is explicit, but a compromised internal caller remains a risk.
- Security mutation and audit writes use separate repositories in some services, so
  a failed audit write can expose an operation/audit consistency gap.
- Forged principal objects are not trusted by themselves; transport authentication
  must establish endpoint principals before message authorization.

## DEFERRED

Human authentication, USER principals, RBAC, organizations/tenants, permission
management, SIEM export, cryptographic tamper evidence, mTLS, and database compromise
mitigations.
