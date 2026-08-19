"""Helpers for classifying IAM principals.

Several checks need to ignore the service agents Google provisions on a
project's behalf — they legitimately hold broad roles and flagging them is pure
noise. The distinction has to be precise in the other direction too: a
customer-owned service account is exactly the principal an auditor cares about,
so a sloppy filter silently drops real findings.
"""

# Google-managed agents whose local part is not the canonical
# ``service-<PROJECT_NUMBER>`` shape.
_GOOGLE_AGENT_DOMAINS = frozenset({
    "cloudservices.gserviceaccount.com",
    "system.gserviceaccount.com",
})

_SERVICE_PREFIX = "service-"


def is_google_managed_agent(member: str) -> bool:
    """True if ``member`` is a service agent Google created and controls.

    Accepts either a bare email or an IAM member string (``serviceAccount:...``).

    The compute (``<num>-compute@developer.gserviceaccount.com``) and App Engine
    (``<project>@appspot.gserviceaccount.com``) default accounts deliberately do
    *not* match: they are customer-controlled and holding Editor on them is a
    real finding.
    """
    email = member.split(":", 1)[-1].strip().lower()
    local, sep, domain = email.partition("@")
    if not sep or not domain.endswith("gserviceaccount.com"):
        return False
    if domain in _GOOGLE_AGENT_DOMAINS or domain.startswith("gcp-sa-"):
        return True
    # ``service-<PROJECT_NUMBER>@<robot-domain>`` is the canonical service-agent
    # shape. The digits are what make this safe: a substring match on
    # "service-" would also swallow a user SA named "payment-service-prod".
    suffix = local[len(_SERVICE_PREFIX):]
    return local.startswith(_SERVICE_PREFIX) and suffix.isdigit()
