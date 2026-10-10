"""In-memory durable-assessment repository semantics for unit tests."""

from ...application.control_plane.assessment_dispatch import RemoteAssessmentRegistry


class InMemoryRemoteAssessmentRepository(RemoteAssessmentRegistry):
    """Named repository adapter; inherits the registry's conflict safeguards."""

