# Phase 3 release gate

Runtime, security, worker topology, recovery documentation, observability, and
the Python 3.11 regression suite are accepted. SQLite single-node support is
the explicit database claim; PostgreSQL remains untested and is not advertised.
No remediation or generic command surface is present. Production deployment is
accepted only with the documented single-scheduler topology and verified
backup/readiness procedures.
