# Release checklist

- Python 3.11 dependency installation verified
- Full `pytest` suite and backend compile pass
- Production CORS/proxy/TLS settings reviewed
- Backup completed and restore procedure available
- Exactly one scheduler instance selected
- Health/readiness and agent HTTPS smoke checks pass
- No remediation or generic command surface introduced
