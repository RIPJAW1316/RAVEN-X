# Database restore runbook

Stop API/scheduler processes, restore the verified backup, start the control
plane, run schema initialization and `/ready`, then verify organization,
endpoint, assessment, schedule, audit, and compliance snapshot counts. Restoring
an older backup may resurrect sessions or credentials; invalidate them according
to incident policy and record that audit history is rolled back to the backup
point.
