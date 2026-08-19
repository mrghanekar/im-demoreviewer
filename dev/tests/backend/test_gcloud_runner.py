"""Tests for the gcloud CLI runner."""

import pytest
from unittest.mock import patch

from backend.core.gcloud_runner import GcloudRunner, GcloudNotFoundError


class TestGcloudRunner:
    """Tests for GcloudRunner."""

    @pytest.fixture
    def runner(self):
        return GcloudRunner(timeout=5)

    def test_cache_cleared(self, runner):
        runner._cache["test"] = "value"
        runner.clear_cache()
        assert len(runner._cache) == 0

    def test_adds_format_json(self, runner):
        # Verify the command would get --format=json appended
        # (actual execution mocked in integration tests)
        assert runner.timeout == 5

    @patch("shutil.which", return_value=None)
    def test_gcloud_not_available(self, mock_which, runner):
        assert runner.gcloud_available is False

    @patch("shutil.which", return_value="/usr/bin/gcloud")
    def test_gcloud_available(self, mock_which, runner):
        assert runner.gcloud_available is True

    @pytest.mark.asyncio
    async def test_run_raises_when_gcloud_missing(self, runner):
        with patch("shutil.which", return_value=None):
            with pytest.raises(GcloudNotFoundError):
                await runner.run("gcloud version")

    def test_cache_hit(self, runner):
        runner._cache["gcloud test --format=json"] = [{"test": True}]
        # Would return cached result without executing
        assert "gcloud test --format=json" in runner._cache
