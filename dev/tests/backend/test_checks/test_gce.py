"""Tests for GCE check modules."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from backend.checks.gce.instance_checks import GCEDeprecatedImages

PROJECT = "test-project"

@pytest.fixture
def runner():
    r = MagicMock()
    r.run = AsyncMock(return_value=[])
    return r

@pytest.mark.asyncio
class TestGCEDeprecatedImages:

    async def test_flags_deprecated_image(self, runner):
        # Mock instance list
        runner.run.side_effect = [
            # 1. Instances
            [{
                "name": "vm-1",
                "zone": "us-central1-a",
                "disks": [{"boot": True, "source": "projects/p/zones/z/disks/d-1"}]
            }],
            # 2. Disk describe
            {"sourceImage": "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-11"},
            # 3. Image describe
            {"deprecated": {"state": "DEPRECATED", "replacement": "debian-12"}}
        ]
        
        check = GCEDeprecatedImages()
        findings = await check.execute(PROJECT, runner)
        
        assert len(findings) == 1
        assert "DEPRECATED" in findings[0].current_state
        assert "debian-12" in findings[0].current_state
        assert findings[0].resource_name == "instances/vm-1"

    async def test_passes_active_image(self, runner):
        runner.run.side_effect = [
            # 1. Instances
            [{
                "name": "vm-2",
                "zone": "us-central1-a",
                "disks": [{"boot": True, "source": "projects/p/zones/z/disks/d-2"}]
            }],
            # 2. Disk describe
            {"sourceImage": "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-12"},
            # 3. Image describe
            {"deprecated": {}} # No state field means active
        ]
        
        check = GCEDeprecatedImages()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_skips_no_instances(self, runner):
        runner.run.return_value = []
        check = GCEDeprecatedImages()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0
