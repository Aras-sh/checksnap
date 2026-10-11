"""Rule catalog for --check-docker: ids, severities and texts in one place (feeds --explain and docs/RULES.md)."""
from __future__ import annotations

from dataclasses import dataclass

from checksnap.core import Severity


@dataclass(frozen=True)
class RuleInfo:
    id: str
    severity: Severity
    title: str
    explanation: str
    fix_hint: str
    needs_snap: bool = False


L, M, H = Severity.LOW, Severity.MEDIUM, Severity.HIGH

_RULES = [
    ("DOC-001", M, "Base image is :latest or unpinned",
     "`FROM python` / `FROM node:latest` resolves to a different image every build, so builds are not reproducible and a surprise upgrade can break production.",
     "Pin a version tag (`python:3.12-slim`), or better a digest (`python:3.12-slim@sha256:...`)."),
    ("DOC-002", M, "Container runs as root (no USER)",
     "Without a `USER` instruction the process runs as root; a bug in the app then gives the attacker root inside the container, and often an easier escape.",
     "Create an unprivileged user (`RUN useradd -r app`) and add `USER app` before CMD/ENTRYPOINT."),
    ("DOC-003", L, "ADD used where COPY would do",
     "`ADD` also downloads URLs and unpacks archives, which is surprising and unverifiable. `COPY` only copies files.",
     "Use `COPY`; for downloads use `curl` with a checksum check in a RUN step."),
    ("DOC-004", L, "apt-get install without --no-install-recommends",
     "Recommended packages are installed too, making the image larger and adding attack surface.",
     "Use `apt-get install -y --no-install-recommends ...`."),
    ("DOC-005", L, "apt-get install without cache cleanup",
     "The package lists stay in the layer and bloat the image.",
     "End the same RUN with `&& rm -rf /var/lib/apt/lists/*` (or use a BuildKit cache mount)."),
    ("DOC-006", M, "apt-get update in a separate layer from install",
     "A cached `apt-get update` layer goes stale; a later `install` layer then fails with 404s or installs outdated packages.",
     "Run `apt-get update && apt-get install -y ...` in a single RUN."),
    ("DOC-007", L, "pip install without --no-cache-dir",
     "pip's download cache is stored in the layer and makes the image larger for no benefit.",
     "Use `pip install --no-cache-dir ...` or set `ENV PIP_NO_CACHE_DIR=1`."),
    ("DOC-008", H, "Secret in ENV or ARG",
     "ENV and ARG values are stored in the image metadata and visible with `docker history` / `docker inspect` to anyone who can pull the image. Only the variable name is shown here.",
     "Use BuildKit secrets (`RUN --mount=type=secret,id=x`) at build time and runtime env / a secret store at run time; rotate the leaked value."),
    ("DOC-009", M, "COPY . . before dependency install (cache busting)",
     "Copying the whole source first means any code edit invalidates the dependency-install layer, so every build re-downloads all dependencies.",
     "Copy only the manifest first (`COPY requirements.txt .`, `package*.json`), install, then `COPY . .`."),
    ("DOC-010", L, "No .dockerignore next to the Dockerfile",
     "Without it the whole directory (.git, .env, node_modules, keys) is sent as build context and can be copied into the image by `COPY . .`.",
     "Add a `.dockerignore` listing `.git`, `.env`, `node_modules`, `__pycache__`, build output."),
    ("DOC-011", L, "No HEALTHCHECK",
     "Without a healthcheck the orchestrator only knows the process is alive, not that it still serves requests.",
     "Add `HEALTHCHECK CMD curl -f http://localhost:PORT/health || exit 1` (or a small script)."),
    ("DOC-012", M, "Remote script piped into a shell (curl | sh)",
     "Running a downloaded script blindly means whoever controls that URL (or a MITM) controls your image; a partial download can also execute a truncated script.",
     "Download to a file, verify a pinned checksum/signature, then run it."),
    ("DOC-013", L, "More than one CMD in a stage",
     "Only the last CMD takes effect; the earlier ones are silently ignored and usually a leftover mistake.",
     "Keep a single CMD per stage (use ENTRYPOINT + CMD if you need a fixed command with default args)."),
    ("DOC-014", M, "SSH port 22 exposed",
     "An SSH daemon inside a container is a second, rarely patched way in, and a sign that the container is being used like a VM.",
     "Remove the sshd and the EXPOSE 22; use `docker exec` / `kubectl exec` for debugging."),
    ("DOC-015", H, "Compose service is privileged",
     "`privileged: true` gives the container nearly all host capabilities and device access; a compromise of the container is a compromise of the host.",
     "Remove it; grant only what is needed with `cap_add: [...]` or `devices:`."),
    ("DOC-016", M, "Compose service uses host networking",
     "`network_mode: host` removes network isolation: the container sees and binds all host interfaces and ports.",
     "Use the default bridge network and publish only the needed ports."),
    ("DOC-017", H, "Docker socket mounted into a container",
     "Access to `/var/run/docker.sock` is root on the host: the container can start a privileged container mounting `/`.",
     "Avoid it; if unavoidable use a socket proxy with a read-only allowlist and never expose that container."),
    ("DOC-018", H, "Secret in compose environment",
     "Passwords and tokens written into the compose file end up in version control and in `docker inspect`. Only the variable name is shown here.",
     "Use `${VAR}` from an untracked `.env`, `env_file`, or Compose `secrets:`; rotate the leaked value."),
    ("DOC-019", M, "Compose image is :latest or unpinned",
     "An untagged image is `latest`: `docker compose pull` can silently switch you to a new major version.",
     "Pin a version tag or digest."),
    ("DOC-020", L, "Compose service has no restart policy",
     "After a crash or host reboot the service stays down.",
     "Add `restart: unless-stopped` (or `on-failure`)."),
    ("DOC-021", L, "Compose service has no healthcheck",
     "Compose cannot wait for the service to be ready (`depends_on: condition: service_healthy`) or report it unhealthy.",
     "Add a `healthcheck:` with `test`, `interval`, `retries`."),
    ("DOC-022", H, "Database port published on all interfaces",
     "`5432:5432` binds 0.0.0.0, so the database is reachable from the whole network (and Docker bypasses most host firewalls).",
     "Bind to loopback (`127.0.0.1:5432:5432`) or drop `ports:` and use the compose network."),
]
RULES: dict[str, RuleInfo] = {r[0]: RuleInfo(*r) for r in _RULES}
