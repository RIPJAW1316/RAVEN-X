# Operational configuration

Use Python 3.11, create a virtual environment, install `requirements.txt`
then `requirements-dev.txt`, and run `python -m pytest -q`. Important settings
include `RAVENX_ENVIRONMENT`, `RAVENX_CORS_ORIGINS`,
`RAVENX_TRUSTED_PROXY`, scheduler enablement/poll interval, compliance bounds,
and optional `RAVENX_COMPLIANCE_RETENTION_ENABLED` with its interval, age,
count, and minimum-keep values. Production validation rejects wildcard CORS,
invalid limits, and unsupported Python runtimes.
