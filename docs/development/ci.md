# Continuous integration

The authoritative Raven-X CI runtime is Python 3.11 on Windows. The workflow
at `.github/workflows/test.yml` installs `requirements-dev.txt`, compiles the
backend, and runs the complete pytest suite without production secrets,
network services, or test deselection.

The expected supported baseline is at least 216 passing tests. Python 3.14 is
not currently part of the required CI matrix.
