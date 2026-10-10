"""Small, local-only options contract for assessment execution."""

from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class AssessmentOptions:
    """Optional scanner selection; ``None`` preserves the legacy full scan."""

    scanner_ids: Optional[Tuple[str, ...]] = None

    def __post_init__(self) -> None:
        if self.scanner_ids is None:
            return
        for scanner_id in self.scanner_ids:
            if not isinstance(scanner_id, str) or not scanner_id.strip():
                raise ValueError("scanner_ids must contain non-empty strings")
