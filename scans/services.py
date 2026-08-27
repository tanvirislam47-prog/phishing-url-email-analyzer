"""Persistence helpers for the scan domain.

This phase stores input and future result data only. No helper in this module
runs an analyzer, calculates a score, contacts a URL, or fabricates a result.
"""

from .models import Scan, ScanStatus, ScanType


def create_pending_scan(scan_type: str, *, input_hash: str = "") -> Scan:
    """Create an empty pending scan record for a later analysis workflow.

    The caller is responsible for supplying a value from ``ScanType``. This
    helper intentionally does not inspect or normalize submitted content.
    """

    return Scan.objects.create(
        scan_type=scan_type,
        status=ScanStatus.PENDING,
        input_hash=input_hash,
    )


__all__ = ["create_pending_scan"]
