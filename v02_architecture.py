"""
Phots V0.2 Pipeline Architecture
=================================

Core infrastructure for the Phots security analysis pipeline.
Defines the PipelineStage and V02Pipeline classes that manage
8 enhancement stages for WordPress security analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from datetime import datetime, timezone


class ImplementationStatus(Enum):
    """Implementation status of a pipeline stage."""

    NO_CREDIT_CARD_REQUIRED = "no_3rd_party"
    USES_FREE = "uses_free"
    USES_PAID = "uses_paid"


class StageStatus(Enum):
    """Execution status of a pipeline stage."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETE = "complete"


@dataclass
class PipelineStage:
    """
    Represents a single stage in the Phots V0.2 pipeline.

    Attributes:
        name: Unique identifier for the stage.
        description: Human-readable description of the stage's purpose.
        status: Current execution status (pending/in_progress/complete).
        implementation_status: Whether the stage uses no third-party,
                               free third-party, or paid third-party tools.
        dependencies: Stage names that must complete before this stage runs.
    """

    name: str
    description: str
    status: StageStatus = field(default=StageStatus.PENDING, init=False)
    implementation_status: ImplementationStatus = field(
        default=ImplementationStatus.NO_CREDIT_CARD_REQUIRED
    )
    dependencies: list[str] = field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    notes: str = ""

    def start(self) -> None:
        """Mark this stage as in_progress."""
        self.status = StageStatus.IN_PROGRESS
        self.started_at = datetime.now(timezone.utc)

    def complete(self) -> None:
        """Mark this stage as complete."""
        self.status = StageStatus.COMPLETE
        self.completed_at = datetime.now(timezone.utc)

    def fail(self) -> None:
        """Reset this stage to pending state."""
        self.status = StageStatus.PENDING
        self.completed_at = None

    def __str__(self) -> str:
        return (
            f"PipelineStage(name={self.name!r}, "
            f"status={self.status.value}, "
            f"implementation_status={self.implementation_status.value})"
        )
