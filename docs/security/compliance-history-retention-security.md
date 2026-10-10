# Compliance history security notes

Tenant authorization is re-evaluated for every history and export request.
Retention is system-only and cannot be invoked through a human hard-delete API.
Whole-aggregate deletion avoids orphan rows; endpoint deletion does not cascade
into history. CSV values are formula-safe and exports are deterministic with a
SHA-256 manifest. Cross-tenant lookup, oversized exports, framework-version
mixing, and misleading remediation interpretations are rejected or made
explicit. Legal holds, durable export storage, cryptographic signatures, and
distributed retention coordination remain deferred.
