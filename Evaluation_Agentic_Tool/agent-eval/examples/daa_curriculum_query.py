import argparse
import sys
from pathlib import Path

from daa_curriculum.workflow import DEFAULT_SOURCE_URL, DaaCurriculumWorkflow


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description="Ask the UIT DAA curriculum workflow.")
    parser.add_argument("question", help="User question about the curriculum")
    parser.add_argument("--source-url", default=DEFAULT_SOURCE_URL)
    parser.add_argument("--fixture-html-path")
    parser.add_argument("--no-crawl-link-pages", action="store_true")
    parser.add_argument("--max-link-pages", type=int, default=120)
    parser.add_argument("--model")
    parser.add_argument("--answer-model")
    parser.add_argument("--review-model")
    parser.add_argument("--base-url", default="http://localhost:11434")
    parser.add_argument("--llm-timeout", type=float, default=30)
    args = parser.parse_args()

    config = {
        "source_url": args.source_url,
        "crawl_link_pages": not args.no_crawl_link_pages,
        "max_link_pages": args.max_link_pages,
        "use_ollama": bool(args.model or args.answer_model or args.review_model),
        "model": args.model,
        "models": {
            "answer": args.answer_model,
            "review": args.review_model,
        },
        "base_url": args.base_url,
        "llm_timeout": args.llm_timeout,
    }
    if args.fixture_html_path:
        config["fixture_html_path"] = str(Path(args.fixture_html_path).resolve())

    workflow = DaaCurriculumWorkflow(config)
    workflow.setup()
    result = workflow.run_scenario(args.question, "user_prompt")
    print(result["result"])


if __name__ == "__main__":
    main()
