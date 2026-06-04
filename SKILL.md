---
name: sca-vuln-verify
description: Atomic helpers for SCA vulnerability verification backed by SCA OpenAPI, EPSS, and CISA KEV.
---

# SCA Vulnerability Verification

Use this skill when an agent needs to verify whether an SCA-reported component vulnerability is likely exploitable in a project context.

## Scope

This package provides a function library, not a forced workflow engine. P0-P2 use SCA OpenAPI as the SCA data source and do not call MCP or platform AI endpoints.

## Public Modules

`sca_vuln_verify.modules.data_fetch`

- `fetch_vuln_detail(client, vuln_id)`
- `fetch_component_detail(client, component_ref, project_id=None)`
- `fetch_project_scan_result(client, task_id, page_size=100, allow_partial=False)`
- `fetch_project_dependency_tree(client, task_id, filters=None)`
- `fetch_component_versions(client, component_ref)`
- `fetch_vuln_affected_components(client, vuln_id)`
- `fetch_component_code_location(client, task_id, component_ref, vuln_id=None)`
- `fetch_vuln_fix_info(client, vuln_id, component_ref=None)`
- `discover_project_tasks(client, project_id, page_size=100, task_scan_range=None)`

`sca_vuln_verify.modules.data_process`

- `parse_purl(purl)`
- `compare_versions(version, affected_range, ecosystem=None)`
- `create_analysis_context(task)`
- `update_analysis_context(context, ...)`
- `analyze_dependency_depth(dependency_tree, component_ref)`
- `check_reachability(component, vulnerability=None, project_context=None)`
- `match_fix_version(current_version, versions, affected_ranges, ecosystem=None)`

`sca_vuln_verify.modules.external_intel`

- `query_epss(cve_id)`
- `check_kev(cve_id)`

`sca_vuln_verify.modules.verdict`

- `suggest_verdict(signals)`

`sca_vuln_verify.modules.output`

- `build_verification_result(...)`
- `validate_verification_result(result)`

`sca_vuln_verify.workflows.batch`

- `verify_batch(client, task_id=None, task_ids=None, project_id=None, task_scan_range=None, ...)`
- `verify_task(client, task_id, progress_callback=None, ...)`

## OpenAPI Client Configuration

Required environment variables:

- `SCA_OPENAPI_BASE_URL`
- `SCA_OPENAPI_ACCESS_KEY`
- `SCA_OPENAPI_SECRET_KEY`

Optional environment variables:

- `SCA_OPENAPI_TIMEOUT_SECONDS`
- `SCA_OPENAPI_MAX_RETRIES`
- `SCA_OPENAPI_SSL_VERIFY`: `true` by default, `false`/`0`/`no`/`off` disables TLS certificate verification for trusted self-signed private deployments, and any other value is treated as a CA bundle path.

## Recommended Analysis Flow

For a component vulnerability, fetch vulnerability detail, fetch component detail, compare the installed version to affected ranges, query EPSS/KEV, inspect dependency depth or code locations when available, ask `suggest_verdict` for a baseline, then assemble a `VerificationResult`.

For a project scan, call `fetch_project_scan_result`, sort component-vulnerability pairs by severity, KEV, EPSS, PoC, and dependency signal, then run the component flow per candidate.

If `discover_project_tasks` fails because module responses only include `task_names[]` and not stable task IDs, pass known `task_ids` to `verify_batch`. Use `task_scan_range` only as an explicit diagnostic fallback because it probes `GET /openapi/v1/tasks/{id}` across the supplied range.

## Baseline Verdict Rules

The baseline rules are suggestions only. An agent may override them, but should explain the reason in `verdict.reasoning`.

- Affected version + KEV + EPSS > 0.9: `exploitable/high`
- Affected version + PoC + direct dependency + reported used: `likely_exploitable/high`
- Affected version + PoC + transitive dependency: `likely_exploitable/medium`
- Affected version + no PoC + direct dependency: `inconclusive/medium`
- Affected version + transitive dependency + reported unused: `likely_not_exploitable/medium`
- Version outside affected range: `not_exploitable/high`
- Missing critical data: `inconclusive/low`

## Safety Notes

- Never treat API failure as evidence that a vulnerability is not exploitable.
- Do not disable TLS verification except for trusted self-signed private SCA servers.
- Never fabricate patch commit IDs; P1 returns solution, suggestion, recommended upgrade version, and available versions only.
- Preserve `source_api`, `request_id`, and `source_module` in evidence when available.
