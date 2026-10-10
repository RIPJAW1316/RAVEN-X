# Control-plane recovery

For database outage, stop writes and restore from the last verified backup.
For scheduler or retention failure, disable the affected worker, inspect safe
logs/metrics, and use the bounded `run_once` operation manually after recovery.
Rollback of schema-incompatible releases requires restoring a pre-upgrade
backup; downgrade migrations are not guaranteed.
