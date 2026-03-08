#!python
import sys
import os
from argparse import ArgumentParser

TAINT_PATH = os.path.realpath(os.path.dirname(os.path.dirname(__file__)))


def _parse_args():
    parser = ArgumentParser()
    parser.add_argument("inp_folder", help="Input folder")
    parser.add_argument("out_folder", help="Output folder")
    return parser.parse_args()


def _main():
    args = _parse_args()
    inp_folder_path = os.path.realpath(args.inp_folder)
    out_folder_path = os.path.realpath(args.out_folder)
    for fname in os.listdir(inp_folder_path):
        if "0x" not in fname:
            continue
        
        inp_file_path = os.path.join(inp_folder_path, fname)
        if not os.path.isfile(inp_file_path):
            continue
        if not fname.endswith(".json"):
            continue
        out_file_path = os.path.join(out_folder_path, fname)
        timeout = 200
        print(f"cd {TAINT_PATH} && timeout {timeout}s python3 -m taint_analysis -m 10 -t {timeout} -d 3 -o {out_file_path} {inp_file_path}")


if __name__ == "__main__":
    _main()
