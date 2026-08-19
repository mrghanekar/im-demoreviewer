"""Tests for GcloudRunner timeout, cancellation, and format-handling edge cases."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.core.gcloud_runner import GcloudRunner
from backend.core.exceptions import GcloudError


def _fake_process(returncode=0, stdout=b"[]", stderr=b"", hang=False):
    """Build a fake asyncio subprocess that returns canned output."""
    proc = MagicMock()
    proc.returncode = returncode
    proc.kill = MagicMock()
    proc.wait = AsyncMock(return_value=returncode)

    if hang:
        async def never(): await asyncio.Future()
        proc.communicate = AsyncMock(side_effect=never)
    else:
        proc.communicate = AsyncMock(return_value=(stdout, stderr))
    return proc


class TestEnsureJsonFormat:
    def test_appends_when_missing(self):
        cmd = "gcloud projects list"
        assert GcloudRunner._ensure_json_format(cmd) == "gcloud projects list --format=json"

    def test_no_double_append_when_already_present(self):
        cmd = "gcloud projects list --format=json"
        assert GcloudRunner._ensure_json_format(cmd) == cmd

    def test_respects_value_format(self):
        cmd = "gcloud projects list --format='value(projectId)'"
        # Must NOT append a second --format
        assert "--format='value(projectId)'" in GcloudRunner._ensure_json_format(cmd)
        assert GcloudRunner._ensure_json_format(cmd).count("--format") == 1

    def test_respects_yaml_format(self):
        cmd = "gcloud projects list --format=yaml"
        assert GcloudRunner._ensure_json_format(cmd) == cmd

    def test_unbalanced_quotes_fallback(self):
        # shlex can't parse this; runner must not crash
        cmd = "gcloud weird --filter='unclosed"
        out = GcloudRunner._ensure_json_format(cmd)
        # Either appended or returned untouched — neither should raise
        assert "--format" in out or out == cmd


@pytest.mark.asyncio
class TestGcloudRunnerTimeout:
    async def test_timeout_raises_gcloud_error(self):
        runner = GcloudRunner(timeout=1)
        with patch("shutil.which", return_value="/usr/bin/gcloud"):
            with patch(
                "backend.core.gcloud_runner.asyncio.create_subprocess_shell",
                AsyncMock(return_value=_fake_process(hang=True)),
            ):
                with pytest.raises(GcloudError) as ei:
                    await runner.run("gcloud something", timeout=1)
                assert "timed out" in str(ei.value).lower()

    async def test_timeout_kills_and_waits_for_process(self):
        runner = GcloudRunner(timeout=1)
        proc = _fake_process(hang=True)
        with patch("shutil.which", return_value="/usr/bin/gcloud"):
            with patch(
                "backend.core.gcloud_runner.asyncio.create_subprocess_shell",
                AsyncMock(return_value=proc),
            ):
                with pytest.raises(GcloudError):
                    await runner.run("gcloud something", timeout=1)
        proc.kill.assert_called_once()
        proc.wait.assert_awaited()

    async def test_cancellation_cleans_up_process(self):
        runner = GcloudRunner(timeout=10)
        proc = _fake_process(hang=True)
        proc.returncode = None  # still running

        with patch("shutil.which", return_value="/usr/bin/gcloud"):
            with patch(
                "backend.core.gcloud_runner.asyncio.create_subprocess_shell",
                AsyncMock(return_value=proc),
            ):
                task = asyncio.create_task(runner.run("gcloud slow"))
                await asyncio.sleep(0.01)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task

        proc.kill.assert_called()
        proc.wait.assert_awaited()
        # Pending map must be cleaned up so the next call doesn't join a dead future
        assert "gcloud slow --format=json" not in runner._pending
