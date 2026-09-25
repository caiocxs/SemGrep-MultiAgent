import argparse
import os
import sys
from pathlib import Path

if __package__ is None or __package__ == "":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from src.agents import agents_general, code_agent
else:
    from .agents import agents_general, code_agent

__all__ = ["agents_general", "code_agent", "main", "run_all"]

MODELS = ["QWEN_CODE", "STARCODER2", "DEEP_SEEK_CODER"]
DATASETS = ["CWES_GOOD", "CWES_BAD"]
DEFAULT_PROMPT = "code_analyser_v2"


def _pending_count(dataset, logs_dir, limit=None):
    """
    Lists the dataset files (no model load required) and returns
    (total_files, pending_files) by checking which logs already exist.
    """
    agents_general.load_dataset(dataset)
    files = agents_general.files or []
    if limit:
        files = files[:limit]

    logs_folder = Path(logs_dir)
    pending = [f for f in files if not (logs_folder / f"log_{f.stem}.json").exists()]
    return len(files), len(pending)


def run_all(models=None, datasets=None, logs_root=None, skip_existing=True, limit=None, prompt_name=DEFAULT_PROMPT):
    """
    Runs the code agent for every (model, dataset) combination sequentially,
    one model loaded at a time, writing each run's logs to its own subfolder.
    Each prompt gets its own logs root (logs/<prompt_name>/ by default) so
    runs with different prompts never overwrite or skip each other's logs.

    Safe to interrupt and re-run: combinations that are already fully logged
    are skipped without loading their model, and partially-done combinations
    resume from the first file that has no log yet.
    """
    models = models or MODELS
    datasets = datasets or DATASETS
    if not logs_root:
        logs_root = os.environ.get("LOGS_LOCATION", "logs/dataset/")
        if prompt_name != "code_analyser":
            logs_root = os.path.join(os.path.dirname(os.path.normpath(logs_root)), prompt_name)

    for model in models:
        for dataset in datasets:
            logs_dir = os.path.join(logs_root, model, dataset)

            if skip_existing:
                total, pending = _pending_count(dataset, logs_dir, limit=limit)
                if total and not pending:
                    print(f"[i] model={model} dataset={dataset} already fully processed ({total}/{total}), skipping model load.")
                    continue

            print(f"\n=== Running model={model} dataset={dataset} ===")

            code_agent.init_agent(model=model, prompt_name=prompt_name, dataset=dataset)

            if limit and code_agent.files:
                code_agent.files = code_agent.files[:limit]
                print(f"[i] Limit applied: processing first {limit} files.")

            code_agent.start_code_analysis(logs_dir=logs_dir, skip_existing=skip_existing)
            print(f"=== Finished model={model} dataset={dataset} ===")


def main():
    parser = argparse.ArgumentParser(description="Run the Code Agent LLM over every model/dataset combination.")
    parser.add_argument("--models", default=None, help=f"Comma-separated model env keys (default: {','.join(MODELS)})")
    parser.add_argument("--datasets", default=None, help=f"Comma-separated dataset env keys (default: {','.join(DATASETS)})")
    parser.add_argument("--prompt", default=DEFAULT_PROMPT, help=f"Prompt file under prompts/ without .md (default: {DEFAULT_PROMPT})")
    parser.add_argument("--logs-root", default=None, help="Root directory for logs, namespaced per model/dataset (default: LOGS_LOCATION for code_analyser, logs/<prompt>/ otherwise)")
    parser.add_argument("--no-skip", action="store_true", help="Do not skip files that already have logs")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of files to process per dataset")

    args = parser.parse_args()

    run_all(
        models=args.models.split(",") if args.models else None,
        datasets=args.datasets.split(",") if args.datasets else None,
        logs_root=args.logs_root,
        skip_existing=not args.no_skip,
        limit=args.limit,
        prompt_name=args.prompt,
    )


if __name__ == "__main__":
    main()
