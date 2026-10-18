"""Domain errors that never include credentials or derived authentication data."""


class J100Error(Exception):
    """Base error for J100 client operations."""


class AuthenticationError(J100Error):
    """The phone rejected authentication or did not establish a session."""


class TransportError(J100Error):
    """The phone could not be reached or its TLS connection failed."""


class ProtocolError(J100Error):
    """The phone returned an unexpected Web UI response."""


class PhoneBusyError(J100Error):
    """The phone has an active call and cannot perform the operation."""


class RestartTimeoutError(J100Error):
    """The restart was accepted but completion was not observed in time."""


class ConfirmationRequiredError(J100Error):
    """A destructive operation requires explicit force confirmation."""


class PasswordValidationError(J100Error):
    """A replacement password does not meet J100 requirements."""
