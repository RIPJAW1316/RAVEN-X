# Compliance retention operations

Retention is application policy, not human self-service deletion. Run the
retention runner in dry-run mode first, review age/count candidates, then run
the bounded deletion once. Framework versions are isolated and minimum newest
snapshots are protected. Retention deletes only complete snapshot aggregates;
it never deletes endpoints, assessments, work, or audit records.
