"""Policy governing which authorization outcomes become audit records.

Rationale
---------
A successful permission check is an implementation detail. A single operator
action performs several of them, so persisting each one turns the security
audit trail into a debug log: on the verification tenant, 122 of 127 rows
(96%) were ``authorization.allowed``, burying five real operator actions.

Successful *operations* are already audited by the service that performs them
(``endpoint.registered``, ``endpoint_group.create``, ``assessment.created``,
``compliance.snapshot.create``, …), so suppressing the permission-check trace
loses no record of what a user actually did.

A **denied** authorization is different. It is evidence of a control doing its
job, and a burst of denials can indicate privilege escalation, a compromised
credential, or tenant-boundary probing. Denials are therefore always recorded
and this policy cannot switch them off.

This matches the policy ``AuthorizationService`` in
``application/ports/control_plane_authorization.py`` has always applied — it
audits only denials. This type makes ``OrganizationRbacAuthorizer`` consistent
with it instead of being the sole outlier.
"""
from dataclasses import dataclass
from typing import FrozenSet


@dataclass(frozen=True)
class AuthorizationAuditPolicy:
    """Decides whether a *successful* authorization is persisted.

    Denials are out of scope here: they are unconditional.
    """

    #: Persist every successful permission check. Off by default; intended as a
    #: short-lived diagnostic during an authorization investigation, not a
    #: steady-state setting.
    record_successful_authorizations: bool = False

    #: Actions whose successful authorization is always recorded, regardless of
    #: the flag above. Reserved for grants that have no operation-level event of
    #: their own and are infrequent enough not to flood the trail. Empty by
    #: default: every action currently reaching this authorizer either has its
    #: own operation event or is a high-frequency read.
    always_recorded_actions: FrozenSet[str] = frozenset()

    def should_record_success(self, action: str) -> bool:
        if self.record_successful_authorizations:
            return True
        return str(action) in self.always_recorded_actions


#: Default: operational and security events only, no permission-check trace.
DEFAULT_AUTHORIZATION_AUDIT_POLICY = AuthorizationAuditPolicy()

#: Opt-in diagnostic profile used when an operator needs the full trace.
DIAGNOSTIC_AUTHORIZATION_AUDIT_POLICY = AuthorizationAuditPolicy(
    record_successful_authorizations=True)
