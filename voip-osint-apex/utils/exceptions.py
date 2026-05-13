"""
VoIP OSINT APEX — Custom Exception Hierarchy
Forensic-grade error classification for audit trails.
"""


class VoIPOSINTError(Exception):
    """Base exception for all VoIP OSINT operations."""
    pass


class APIError(VoIPOSINTError):
    """Remote API returned an error or unexpected response."""

    def __init__(self, service: str, message: str, status_code: int = None):
        self.service = service
        self.status_code = status_code
        super().__init__(f"[{service}] {message}" + (f" (HTTP {status_code})" if status_code else ""))


class RateLimitError(APIError):
    """API rate limit exceeded (HTTP 429)."""

    def __init__(self, service: str, retry_after: int = None):
        self.retry_after = retry_after
        msg = "Rate limit exceeded"
        if retry_after:
            msg += f" — retry after {retry_after}s"
        super().__init__(service, msg, status_code=429)


class AuthenticationError(APIError):
    """API key missing, invalid, or expired."""

    def __init__(self, service: str):
        super().__init__(service, "Authentication failed — check API key in .env", status_code=401)


class NetworkError(VoIPOSINTError):
    """Network connectivity failure (timeout, DNS, connection refused)."""

    def __init__(self, service: str, original: Exception = None):
        self.original = original
        msg = f"[{service}] Network error"
        if original:
            msg += f": {type(original).__name__}: {original}"
        super().__init__(msg)


class ParseError(VoIPOSINTError):
    """Failed to parse response data or packet content."""

    def __init__(self, source: str, message: str = "Malformed data"):
        self.source = source
        super().__init__(f"[{source}] Parse error: {message}")


class ForensicIntegrityError(VoIPOSINTError):
    """Evidence hash mismatch or data tampering detected."""

    def __init__(self, file_path: str, expected: str = None, actual: str = None):
        self.file_path = file_path
        msg = f"Integrity violation: {file_path}"
        if expected and actual:
            msg += f" (expected={expected[:16]}… got={actual[:16]}…)"
        super().__init__(msg)
