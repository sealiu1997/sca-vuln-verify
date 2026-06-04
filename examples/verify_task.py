"""Run batch SCA vulnerability verification for one task or project."""

from __future__ import annotations

import argparse
import json
import sys

from sca_vuln_verify.adapters.sca_openapi import SCAOpenAPIClient
from sca_vuln_verify.workflows.batch import verify_batch


def print_progress(event: dict[str, object]) -> None:
    name = event.get("event")
    task_id = event.get("task_id")
    if name == "candidate_verified":
        print(
            "task {task_id}: verified {index}/{total} {vulnerability_id} -> {verdict}".format(**event),
            file=sys.stderr,
        )
    elif task_id is not None:
        print(f"task {task_id}: {name}", file=sys.stderr)
    else:
        print(str(name), file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify SCA task vulnerabilities.")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--task-id", type=int, action="append", dest="task_ids")
    target.add_argument("--project-id")
    parser.add_argument("--task-scan-range", type=int, nargs=2, metavar=("START_ID", "END_ID"))
    parser.add_argument("--output-dir", default="sca-vuln-verify-output")
    parser.add_argument("--top-n", type=int)
    parser.add_argument("--severity", action="append", dest="severities")
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification for self-signed SCA servers.",
    )
    parser.add_argument("--progress", action="store_true", help="Print progress events to stderr.")
    args = parser.parse_args()

    task_scan_range = tuple(args.task_scan_range) if args.task_scan_range else None
    with SCAOpenAPIClient(verify=not args.no_verify_ssl) as client:
        result = verify_batch(
            client,
            task_ids=args.task_ids,
            project_id=args.project_id,
            task_scan_range=task_scan_range,
            output_dir=args.output_dir,
            top_n=args.top_n,
            severities=args.severities,
            progress_callback=print_progress if args.progress else None,
        )

    print(json.dumps(result["tasks"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
