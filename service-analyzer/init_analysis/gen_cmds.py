#!python
import sys
import os
from argparse import ArgumentParser

from .collect import examine_workspace


ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

def _parse_args():
    parser = ArgumentParser()
    parser.add_argument("inp_folder", help="Input folder")
    parser.add_argument("out_folder", help="Output folder")
    parser.add_argument("--force", action="store_true", help="All targets even success")
    return parser.parse_args()


def _main():
    args = _parse_args()
    inp_folder_path = os.path.realpath(args.inp_folder)
    out_folder_path = os.path.realpath(args.out_folder)

    for vendor in os.listdir(inp_folder_path):
        dir_path = os.path.join(inp_folder_path, vendor)
        if not os.path.isdir(dir_path):
            continue
        for image in os.listdir(dir_path):
            inp_file_path = os.path.join(dir_path, image)
            if not os.path.isfile(inp_file_path):
                continue
            workspace = os.path.join(out_folder_path, vendor, image)
            res = examine_workspace(workspace)

            if args.force or res["status"] != "Success":
                print(
                    f"cd {ROOT} && python3 -m init_analysis --workspace {workspace} {inp_file_path}"
                )


if __name__ == "__main__":
    _main()
