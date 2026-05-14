"""
VoIP OSINT APEX v3.0 — Custom Exception Hierarchy
All platform exceptions inherit from VoipOSINTError.
"""


class VoipOSINTError(Exception):
    """Base exception for all VoIP OSINT APEX errors."""
    pass


class APIKeyMissingError(VoipOSINTError):
    """Raised when a required API key is not configured."""
    def __init__(self, key_name: str):
        self.key_name = key_name
        super().__init__(f"API key not configured: {key_name}. Set it in your .env file.")


class RateLimitError(VoipOSINTError):
    """Raised when an API rate limit is exceeded."""
    def __init__(self, api_name: str, retry_after: float = 0):
        self.api_name = api_name
        self.retry_after = retry_after
        super().__init__(f"Rate limit hit for {api_name}. Retry after {retry_after:.1f}s.")


class NetworkError(VoipOSINTError):
    """Raised on network connectivity failures."""
    def __init__(self, url: str, reason: str):
        self.url = url
        self.reason = reason
        super().__init__(f"Network error reaching {url}: {reason}")


class ParseError(VoipOSINTError):
    """Raised when data parsing fails."""
    def __init__(self, source: str, reason: str):
        self.source = source
        self.reason = reason
        super().__init__(f"Parse error in {source}: {reason}")


class CacheError(VoipOSINTError):
    """Raised on cache read/write failures."""
    def __init__(self, operation: str, reason: str):
        self.operation = operation
        self.reason = reason
        super().__init__(f"Cache {operation} failed: {reason}")


class ScanError(VoipOSINTError):
    """Raised when a network scan operation fails."""
    def __init__(self, target: str, reason: str):
        self.target = target
        self.reason = reason
        super().__init__(f"Scan failed for {target}: {reason}")


class ReportError(VoipOSINTError):
    """Raised when report generation fails."""
    pass


class DatabaseError(VoipOSINTError):
    """Raised on case database failures."""
    pass
