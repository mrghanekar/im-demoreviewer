"""Tests for WebSocket scan_token authentication."""


from backend.api.routes.websocket import (
    generate_scan_token,
    verify_scan_token,
    _scan_tokens,
)


class TestScanTokenAuth:
    def setup_method(self):
        _scan_tokens.clear()

    def test_generate_and_verify(self):
        token = generate_scan_token("scan-abc")
        assert token
        assert verify_scan_token("scan-abc", token) is True

    def test_wrong_token_rejected(self):
        generate_scan_token("scan-abc")
        assert verify_scan_token("scan-abc", "not-the-token") is False

    def test_unknown_scan_rejected(self):
        # No token was generated for this scan id
        assert verify_scan_token("scan-zzz", "anything") is False

    def test_empty_token_rejected(self):
        generate_scan_token("scan-abc")
        assert verify_scan_token("scan-abc", "") is False

    def test_tokens_are_unique_per_scan(self):
        t1 = generate_scan_token("scan-1")
        t2 = generate_scan_token("scan-2")
        assert t1 != t2

    def test_cross_scan_token_does_not_validate(self):
        t1 = generate_scan_token("scan-1")
        generate_scan_token("scan-2")
        assert verify_scan_token("scan-2", t1) is False
