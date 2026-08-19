"""Static metadata invariants for every registered check.

The catalog API shows each check's *declared* class attributes while scan
findings carry the *emitted* values, so drift between the two means users
see one severity in the scan form and another in the results. These tests
AST-walk every check class so that drift, malformed fix templates, and
gcloud commands the runner cannot execute all fail CI with the offending
check named.
"""

import ast
import inspect
import shlex
import string
import textwrap

from backend.checks.registry import discover_checks

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Checks that deliberately compute per-finding severity (escalation is
# documented in their class docstrings; declared severity is the worst case).
EXPECTED_COMPUTED_SEVERITIES = {"AR-005", "PATCH-004"}

# The runner executes commands with create_subprocess_exec after shlex.split,
# so shell features silently break instead of erroring.
SHELL_METACHARACTERS = ("|", ";", "&&", "`", "$(")

# `--location=-` is rejected by `gcloud recommender` and `gcloud kms keyrings
# list` (it left four checks permanently inert), but the Notebooks/Workbench
# APIs document `locations/-` as their all-locations wildcard and gcloud
# accepts it there.
WILDCARD_LOCATION_OK_PREFIXES = ("gcloud notebooks ", "gcloud workbench ")


def _checks():
    return discover_checks()


def _source_file(check) -> str:
    return inspect.getsourcefile(type(check)) or "<unknown>"


def _class_tree(check) -> ast.ClassDef:
    source = textwrap.dedent(inspect.getsource(type(check)))
    return ast.parse(source).body[0]


def _call_name(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _iter_runner_commands():
    """Yield (module_file, lineno, class_name, command) for every statically
    resolvable string handed to gcloud_runner.run()."""
    seen_modules = {}
    for check in _checks().values():
        module = inspect.getmodule(type(check))
        if module is None or module.__name__ in seen_modules:
            continue
        seen_modules[module.__name__] = True
        module_file = inspect.getsourcefile(module) or "<unknown>"
        tree = ast.parse(inspect.getsource(module))
        classes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and _call_name(node) == "run"):
                continue
            for arg in node.args:
                command = _static_string(arg)
                if command is None:
                    continue
                owner = next(
                    (c.name for c in classes
                     if c.lineno <= node.lineno <= (c.end_lineno or c.lineno)),
                    module.__name__,
                )
                yield module_file, node.lineno, owner, command


def _static_string(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            else:
                parts.append("x")
        return "".join(parts)
    return None


def test_emitted_severity_never_exceeds_declared():
    """A finding more severe than the catalog advertises means the scan-form
    badge understates what the user will actually get."""
    violations: list[str] = []
    computed: dict[str, int] = {}

    for check_id, check in _checks().items():
        declared = SEVERITY_RANK[check.severity.name]
        for node in ast.walk(_class_tree(check)):
            if not (isinstance(node, ast.Call)
                    and _call_name(node) in ("CheckResult", "Finding")):
                continue
            for kw in node.keywords:
                if kw.arg != "severity":
                    continue
                value = kw.value
                if (isinstance(value, ast.Attribute)
                        and isinstance(value.value, ast.Name)
                        and value.value.id == "Severity"):
                    emitted = SEVERITY_RANK[value.attr]
                    if emitted > declared:
                        violations.append(
                            f"{check_id} ({_source_file(check)}): emits "
                            f"Severity.{value.attr} but declares "
                            f"Severity.{check.severity.name}"
                        )
                elif (isinstance(value, ast.Attribute)
                        and value.attr == "severity"):
                    pass  # self.severity — equal to declared by definition
                else:
                    computed[check_id] = computed.get(check_id, 0) + 1

    assert not violations, "Emitted severity exceeds declared:\n" + "\n".join(violations)
    assert set(computed) == EXPECTED_COMPUTED_SEVERITIES, (
        f"Checks with computed severity expressions changed: found "
        f"{sorted(computed)}, expected {sorted(EXPECTED_COMPUTED_SEVERITIES)}. "
        f"If the new one is a deliberate escalation, document it in the class "
        f"docstring and add it here."
    )


def test_required_metadata_is_populated():
    missing: list[str] = []
    for check_id, check in _checks().items():
        for attr in ("id", "title", "description", "severity", "category",
                     "service", "service_category"):
            if not getattr(check, attr, None):
                missing.append(f"{check_id} ({_source_file(check)}): empty {attr!r}")
    assert not missing, "Checks with empty metadata:\n" + "\n".join(missing)


def test_references_are_https_urls():
    bad: list[str] = []
    for check_id, check in _checks().items():
        for ref in check.references:
            if not ref.startswith("https://"):
                bad.append(f"{check_id} ({_source_file(check)}): {ref!r}")
    assert not bad, "Non-https references:\n" + "\n".join(bad)


def test_fix_command_templates_render():
    """A template with a stray brace or positional field raises when
    build_fix_command runs, which surfaces as a missing fix in the UI."""
    broken: list[str] = []
    for check_id, check in _checks().items():
        template = check.fix_command_template
        if not template:
            continue
        try:
            fields = [f for _, f, _, _ in string.Formatter().parse(template)
                      if f is not None]
        except ValueError as e:
            broken.append(f"{check_id} ({_source_file(check)}): unparseable template: {e}")
            continue
        if any(not f or f.isdigit() for f in fields):
            broken.append(
                f"{check_id} ({_source_file(check)}): positional placeholder "
                f"in template {template!r}"
            )
            continue
        try:
            template.format(**{f: "placeholder-value" for f in fields})
        except (KeyError, IndexError, ValueError) as e:
            broken.append(f"{check_id} ({_source_file(check)}): {e!r} in {template!r}")
    assert not broken, "Broken fix_command_templates:\n" + "\n".join(broken)


def _all_executable_commands():
    for module_file, lineno, owner, command in _iter_runner_commands():
        yield f"{owner} ({module_file}:{lineno})", command
    for check_id, check in _checks().items():
        if check.gcloud_command:
            yield f"{check_id} ({_source_file(check)})", check.gcloud_command


def test_runner_commands_are_exec_safe():
    bad: list[str] = []
    for where, command in _all_executable_commands():
        for meta in SHELL_METACHARACTERS:
            if meta in command:
                bad.append(f"{where}: shell metacharacter {meta!r} in {command!r}")
        try:
            shlex.split(command, posix=True)
        except ValueError as e:
            bad.append(f"{where}: not shlex-parseable ({e}): {command!r}")
    assert not bad, (
        "Commands the runner cannot execute (create_subprocess_exec runs no "
        "shell):\n" + "\n".join(bad)
    )


def test_no_invalid_wildcard_location():
    bad: list[str] = []
    for where, command in _all_executable_commands():
        if "--location=-" not in command:
            continue
        if command.lstrip().startswith(WILDCARD_LOCATION_OK_PREFIXES):
            continue
        bad.append(f"{where}: {command!r}")
    assert not bad, (
        "`--location=-` is not a valid wildcard for these gcloud surfaces; "
        "the command will fail on every scan:\n" + "\n".join(bad)
    )
