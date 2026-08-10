class Task5Error(Exception):
    """Base exception for Task 5 runtime authorization failures."""


class InterfaceError(Task5Error):
    pass


class DecisionVerificationError(Task5Error):
    pass


class LeaseIssuanceError(Task5Error):
    pass


class LeaseValidationError(Task5Error):
    pass


class RevocationError(Task5Error):
    pass


class ReplayError(Task5Error):
    pass


class SenderConstraintError(Task5Error):
    pass


class IdempotencyError(Task5Error):
    pass
