"""Run batch SCA vulnerability verification for one task or project."""

from __future__ import annotations

import argparse
import json

from sca_vuln_verify.adapters.sca_openapi import SCAOpenAPIClient
from sca_vuln_verify.workflows.batch import verify_batch


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify SCA task vulnerabilities.")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--task-id", type=int)
    target.add_argument("--project-id")
    parser.add_argument("--output-dir", default="sca-vuln-verify-output")
    parser.add_argument("--top-n", type=int)
    parser.add_argument("--severity", action="append", dest="severities")
    args = parser.parse_args()

    with SCAOpenAPIClient() as client:
        result = verify_batch(
            client,
            task_id=args.task_id,
            project_id=args.project_id,
            output_dir=args.output_dir,
            top_n=args.top_n,
            severities=args.severities,
        )

    print(json.dumps(result["tasks"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
