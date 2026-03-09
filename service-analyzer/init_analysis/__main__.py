"""
Analyze the init program of a firmware image to infer service information
"""

import sys
import os
from argparse import ArgumentParser

from .analyzer import InitAnalyzer


WORKSPACE = "/tmp/init_analysis"


def _main():
    args = _parse_args()
    
    # set stack limit
    sys.setrecursionlimit(65536)

    img_path = args.img_path
    if not os.path.isfile(img_path):
        print(f"Cannot find file: {img_path}")
        sys.exit(1)

    os.makedirs(args.workspace, exist_ok=True)

    artifact_path = os.path.join(os.path.dirname(__file__), "artifacts")
    analyzer = InitAnalyzer(args.workspace, img_path, artifact_path)
    analyzer.run(max_runs=args.max_runs, timeout_per_run=args.timeout, inspect=args.inspect)


def _parse_args():
    parser = ArgumentParser(description="Init Program Analyzer")
    parser.add_argument("img_path", help="Path to firmware image")
    parser.add_argument("--brand", help="Brand of the firmware image")
    # parser.add_argument("--no-emu", action="store_true", help="Run without emulation")
    parser.add_argument("-i", "--inspect", action="store_true", help="Inspect the emulation environment")
    parser.add_argument(
        "--workspace", help="Path to workspace directory", default=WORKSPACE
    )
    parser.add_argument(
        "--timeout", type=int, help="Timeout for each run (in seconds)", default=180
    )
    parser.add_argument(
        "--max-runs", type=int, help="Maximum number of patch loop runs", default=3
    )
    return parser.parse_args()


def _get_brand_from_path(img_path):
    return os.path.basename(os.path.dirname(img_path))


if __name__ == "__main__":
    _main()
