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
```

Run tests:

```bash
python -m pytest -v
```

Run a task verification:

```bash
python examples/verify_task.py --task-id 123 --output-dir sca-vuln-verify-output
```
