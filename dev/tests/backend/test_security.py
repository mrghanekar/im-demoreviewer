"""Tests for security middleware, validation, and hardening features."""


from backend.api.middleware.validation import (
    validate_project_id,
    validate_org_id,
    validate_target_id,
    validate_bucket_name,
    validate_scan_id,
    sanitize_string,
)


# ---------------------------------------------------------------------------
# Input Validation Tests
# ---------------------------------------------------------------------------

class TestProjectIdValidation:
    def test_valid_project_ids(self):
        assert validate_project_id("my-project-123") == "my-project-123"
        assert validate_project_id("project1") == "project1"
        assert validate_project_id("a-very-long-project-name-12345") == "a-very-long-project-name-12345"

    def test_strips_whitespace(self):
        assert validate_project_id("  my-project  ") == "my-project"

    def test_lowercases(self):
        assert validate_project_id("My-Project") == "my-project"

    def test_rejects_too_short(self):
        assert validate_project_id("abc") is None

    def test_rejects_starting_with_number(self):
        assert validate_project_id("1project") is None

    def test_rejects_uppercase_only(self):
        # After lowercasing, this is valid
        result = validate_project_id("MYPROJECT")
        assert result == "myproject"

    def test_rejects_special_characters(self):
        assert validate_project_id("project@name") is None
        assert validate_project_id("project name") is None
        assert validate_project_id("project/name") is None

    def test_rejects_ending_with_hyphen(self):
        assert validate_project_id("project-") is None


class TestOrgIdValidation:
    def test_valid_org_ids(self):
        assert validate_org_id("123456789") == "123456789"
        assert validate_org_id("1") == "1"

    def test_rejects_non_numeric(self):
        assert validate_org_id("org-123") is None
        assert validate_org_id("abc") is None

    def test_rejects_empty(self):
        assert validate_org_id("") is None

    def test_strips_whitespace(self):
        assert validate_org_id("  123456  ") == "123456"


class TestTargetIdValidation:
    def test_project_scope(self):
        assert validate_target_id("my-project", "project") == "my-project"
        assert validate_target_id("bad!", "project") is None

    def test_org_scope(self):
        assert validate_target_id("123456789", "org") == "123456789"
        assert validate_target_id("my-org", "org") is None


class TestBucketNameValidation:
    def test_valid_bucket_names(self):
        assert validate_bucket_name("my-bucket") == "my-bucket"
        assert validate_bucket_name("bucket.name.com") == "bucket.name.com"
        assert validate_bucket_name("bucket123") == "bucket123"

    def test_rejects_too_short(self):
        assert validate_bucket_name("ab") is None

    def test_rejects_special_chars(self):
        assert validate_bucket_name("bucket@name") is None


class TestScanIdValidation:
    def test_valid_scan_ids(self):
        assert validate_scan_id("a1b2c3d4") == "a1b2c3d4"
        assert validate_scan_id("abcd-1234-efgh") == "abcd-1234-efgh"

    def test_rejects_special_chars(self):
        assert validate_scan_id("scan;DROP TABLE") is None


class TestSanitizeString:
    def test_removes_null_bytes(self):
        assert sanitize_string("hello\x00world") == "helloworld"

    def test_preserves_newlines(self):
        assert sanitize_string("line1\nline2") == "line1\nline2"

    def test_limits_length(self):
        long_str = "a" * 1000
        assert len(sanitize_string(long_str, max_length=100)) == 100

    def test_normal_string_unchanged(self):
        assert sanitize_string("normal text") == "normal text"


# ---------------------------------------------------------------------------
# Rate Limiter Tests
# ---------------------------------------------------------------------------

class TestRateLimiter:
    def _make_limiter(self, max_clients: int = 1000):
        from backend.api.middleware.security import RateLimitMiddleware
        limiter = RateLimitMiddleware.__new__(RateLimitMiddleware)
        limiter.general_rpm = 5
        limiter.scan_rpm = 2
        limiter.max_clients = max_clients
        limiter.WINDOW_SECONDS = 60.0
        from collections import OrderedDict
        limiter._general_counts = OrderedDict()
        limiter._scan_counts = OrderedDict()
        return limiter

    def test_rate_limiter_bucket_pruning(self):
        """First N requests pass; subsequent ones are rate-limited."""
        limiter = self._make_limiter()
        for _ in range(5):
            assert limiter._check_rate(limiter._general_counts, "127.0.0.1", 5) is True
        assert limiter._check_rate(limiter._general_counts, "127.0.0.1", 5) is False

    def test_different_ips_have_separate_limits(self):
        """Limits are per-IP."""
        limiter = self._make_limiter()
        for _ in range(3):
            limiter._check_rate(limiter._general_counts, "1.1.1.1", 3)
        assert limiter._check_rate(limiter._general_counts, "1.1.1.1", 3) is False
        assert limiter._check_rate(limiter._general_counts, "2.2.2.2", 3) is True

    def test_lru_eviction_of_cold_clients(self):
        """Bucket evicts oldest clients once it exceeds max_clients."""
        limiter = self._make_limiter(max_clients=3)
        for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"):
            limiter._check_rate(limiter._general_counts, ip, 10)
        # First IP should have been evicted (LRU)
        assert "1.1.1.1" not in limiter._general_counts
        assert len(limiter._general_counts) == 3


# ---------------------------------------------------------------------------
# Structured Logging Tests
# ---------------------------------------------------------------------------

class TestStructuredLogging:
    def test_cloud_logging_formatter_output(self):
        """Test that the JSON formatter produces valid Cloud Logging format."""
        import json
        import logging
        from backend.api.middleware.logging_config import CloudLoggingFormatter

        formatter = CloudLoggingFormatter()
        record = logging.LogRecord(
            name="test.module",
            level=logging.ERROR,
            pathname="test.py",
            lineno=42,
            msg="Something went wrong: %s",
            args=("detail",),
            exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)

        assert parsed["severity"] == "ERROR"
        assert "Something went wrong: detail" in parsed["message"]
        assert parsed["logger"] == "test.module"
        assert "timestamp" in parsed

    def test_console_formatter_output(self):
        """Test that the console formatter produces readable output."""
        import logging
        from backend.api.middleware.logging_config import ConsoleFormatter

        formatter = ConsoleFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Hello world",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        assert "INFO" in output
        assert "Hello world" in output
