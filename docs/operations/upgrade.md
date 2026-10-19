# Upgrade procedure

Run the supported Python 3.13 test suite and compile check, create and verify
a sensitive database backup, stop or safely drain workers, install dependencies,
initialize additive schema changes, start the API, check `/ready`, and perform
authenticated smoke tests. Keep the prior release available for rollback.
