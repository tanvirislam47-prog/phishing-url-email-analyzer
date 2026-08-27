"""Application services reserved for later scan workflow phases.

Phase 1 deliberately performs no analysis, creates no scan records, and does
not return fabricated scores or verdicts.
"""


class PhaseOneOnlyError(RuntimeError):
    """Raised if a future caller attempts to run a scan before Phase 2."""


__all__ = ["PhaseOneOnlyError"]
