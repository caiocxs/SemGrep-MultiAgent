import argparse
import os
import sys

# Support direct script execution as well as package module execution
if __package__ is None or __package__ == "":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from src.agents import code_agent
else:
    from .agents import code_agent


def process_good_files(dataset="CWES_GOOD", model="QWEN_CODE", logs_dir=None, skip_existing=True, limit=None):
    """
    Initializes the code agent on the good files dataset and performs vulnerability analysis.
    """
    print(f"=== Starting Analysis for GOOD files (dataset: {dataset}) ===")
    code_agent.init_agent(model=model, prompt_name="code_analyser", dataset=dataset)

    if limit and code_agent.files:
        code_agent.files = code_agent.files[:limit]
        print(f"[i] Limit applied: processing first {limit} files.")

    code_agent.start_code_analysis(logs_dir=logs_dir, skip_existing=skip_existing)
    print("=== Finished processing GOOD files dataset ===")


def main():
    parser = argparse.ArgumentParser(description="Process good CWE files using the Code Agent LLM.")
    parser.add_argument("--dataset", default="CWES_GOOD", help="Dataset env key or path (default: CWES_GOOD)")
    parser.add_argument("--model", default="QWEN_CODE", help="Model env key or name (default: QWEN_CODE)")
    parser.add_argument("--logs-dir", default=None, help="Directory to store output logs (default: from LOGS_LOCATION env)")
    parser.add_argument("--no-skip", action="store_true", help="Do not skip files that already have logs")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of files to process")

    args = parser.parse_args()

    process_good_files(
        dataset=args.dataset,
        model=args.model,
        logs_dir=args.logs_dir,
        skip_existing=not args.no_skip,
        limit=args.limit
    )


if __name__ == "__main__":
    main()
