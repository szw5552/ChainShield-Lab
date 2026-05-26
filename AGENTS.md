# ChainShield Lab Agent Instructions

## Project Intent

- This repository is a demonstrable PoC for AI-assisted npm supply-chain defense.
- Keep the scope focused on the three demo gates: Snyk dependency vulnerability checks, Socket dependency policy checks, and OpenShell runtime containment.
- Prefer the smallest implementation that produces observable, repeatable evidence for an allow or deny decision.
- Do not turn this PoC into a production CI/CD platform, SOC/SIEM integration, or general malware-analysis framework unless a future spec explicitly requires it.

## Planning and Language

- Before implementing feature work, create or update the relevant Spec Kit artifacts and follow the current plan.
- Write Spec Kit user-facing artifacts in Traditional Chinese (zh-TW), including acceptance scenarios, quickstarts, research notes, and tasks.
- Keep the constitution in English and treat it as the source of truth for TDD, BDD, KISS, UX consistency, and performance/evidence gates.
- Express user-facing behavior as Given/When/Then scenarios before implementation planning.

## Safety Boundaries

- Never execute the malicious PoC package or its `postinstall` behavior directly on the host system.
- Run install-time attack demonstrations only inside the intended sandbox/container flow with explicit filesystem and network restrictions.
- Do not use real secrets, credentials, SSH keys, cloud profiles, or personal environment files in fixtures, tests, logs, or reports.
- Do not publish the PoC package to a public registry. Keep malicious fixtures local and clearly labeled as PoC-only.
- Do not commit API tokens, auth files, scanner credentials, sandbox logs containing secrets, or machine-specific sensitive paths.

## Implementation Rules

- Use npm-focused fixtures unless the active spec explicitly expands package manager scope.
- Keep Supervisor decisions evidence-driven and traceable to Snyk reports, Socket reports, OpenShell deny logs, or documented manual observations.
- Treat Snyk and Socket login/network requirements as optional runtime dependencies; provide report fixtures or manual verification paths when live scans are unavailable.
- Verify actual CLI flags and policy schemas for NemoClaw/OpenShell, Snyk, and Socket before depending on them in scripts or docs.
- Keep generated reports, tarballs, logs, and temporary demo outputs out of source control unless they are intentional sanitized fixtures.

## Testing and Evidence

- Follow test-first development for automatable behavior: write the failing test, verify red, implement the minimum passing change, then refactor.
- For user-facing agent decisions, include BDD acceptance scenarios and make each scenario independently demonstrable.
- Document any behavior that cannot be automated with a clear manual verification path and expected evidence.
- Capture enough structured evidence to explain every allow or deny decision without rerunning the full demo.
- Include performance or runtime expectations for scanner, install, sandbox, and report-processing flows, or explicitly mark them not applicable with rationale.

<!-- SPECKIT START -->
Current implementation plan: `specs/001-orbstack-sandbox-gates/plan.md`.

For additional context about technologies to be used, project structure,
shell commands, and other important information, read the current plan before
implementation.

Spec Kit user-facing artifacts such as spec.md, plan.md, tasks.md,
research.md, data-model.md, quickstart.md, and checklists must be written in
Traditional Chinese (zh-TW). The project constitution must remain in English.
Follow the constitution's TDD, BDD, KISS, UX consistency, and performance gates.
<!-- SPECKIT END -->
