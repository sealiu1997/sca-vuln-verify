# SCA Vulnerability Verification

This package provides atomic helper functions for SCA vulnerability verification.
It implements OpenAPI signing, an OpenAPI client, normalized schemas, identifier
helpers, OpenAPI-backed data fetch, EPSS/KEV external intelligence, baseline
verdict rules, heuristic reachability, schema-validated verification result
output, and batch task/project verification workflows.

Required OpenAPI environment variables:

```bash
SCA_OPENAPI_BASE_URL=https://sca.example.com
SCA_OPENAPI_ACCESS_KEY=...
SCA_OPENAPI_SECRET_KEY=...
# Optional. Use false only for trusted self-signed private SCA servers.
SCA_OPENAPI_SSL_VERIFY=true
```

Run tests:

```bash
python -m pytest -v
```

Run a task verification:

```bash
python examples/verify_task.py --task-id 123 --output-dir sca-vuln-verify-output
```

Run several known tasks, or use a self-signed internal server:

```bash
python examples/verify_task.py --task-id 3 --task-id 4 --no-verify-ssl --progress
```

When project task discovery lacks stable task IDs, use a project plus an explicit
diagnostic scan range:

```bash
python examples/verify_task.py --project-id 4 --task-scan-range 1 100 --no-verify-ssl
```
