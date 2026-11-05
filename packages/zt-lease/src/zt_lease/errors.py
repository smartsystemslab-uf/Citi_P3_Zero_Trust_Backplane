class LeaseError(Exception):
    """Base exception for Permit Lease runtime authorization failures."""


class InterfaceError(LeaseError):
    pass


class DecisionVerificationError(LeaseError):
    pass


class LeaseIssuanceError(LeaseError):
    pass


class LeaseValidationError(LeaseError):
    pass


class RevocationError(LeaseError):
    pass


class ReplayError(LeaseError):
    pass


class SenderConstraintError(LeaseError):
    pass


class IdempotencyError(LeaseError):
    pass
