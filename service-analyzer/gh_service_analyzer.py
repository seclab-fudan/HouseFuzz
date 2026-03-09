#!python3
#-*- coding: utf-8 -*-
""" This module re-implement the service analysis logic of Greenhouse
"""

import os
import sys
import subprocess
from subprocess import PIPE
from argparse import ArgumentParser
import json


POTENTIAL_HTTPSERV = [
    "httpd",
    "uhttpd",
    "lighttpd",
    "jjhttpd",
    "shttpd",
    "thttpd",
    "minihttpd",
    "mini_httpd",
    "mini_httpds",
    "dhttpd",
    "alphapd",
    "goahead",
    "boa",
    "appweb",
    "shgw_httpd",
    "tenda_httpd",
    "funjsq_httpd",
    "webs",
    "hunt_server",
    "hydra",
]
POTENTIAL_UPNPSERV = [
    "miniupnpd",
    "miniupnpc",
    "mini_upnpd",
    "miniupnpd_ap",
    "miniupnpd_wsc",
    "upnp",
    "upnpc",
    "upnpd",
    "upnpc-static",
    "upnprenderer",
    "bcmupnp",
    "wscupnpd",
    "upnp_app",
    "upnp_igd",
    "upnp_tv_devices",
]
POTENTIAL_DNSSERV = ["ddnsd", "dnsmasq"]
POTENTIAL_DHCPSERV = ["udhcpd", "dnsmasq"]


class GHServiceAnalyzer:
    """
    Reimplement the service analysis logic of Greenhouse
    """

    @classmethod
    def find_binary(cls, fs_path, rehost_type):
        """Find the service binary in the filesystem (get_target_binary)"""
        potential_binaries = cls._get_potential_binaries(rehost_type)
        pot_targets = dict()
        for root, _, files in os.walk(fs_path, topdown=False):
            for name in files:
                if name.lower() in potential_binaries:
                    if name.lower() not in pot_targets:
                        pot_targets[name.lower()] = []
                    pot_targets[name.lower()].append(os.path.join(root, name))

        # return "best" match in order listed in potential_binaries
        for binary in potential_binaries:
            if binary in pot_targets:
                for bin_path in pot_targets[binary]:
                    sp = subprocess.run(
                        ["file", bin_path], stdout=PIPE, stderr=PIPE, check=False
                    )
                    stdout = sp.stdout
                    details = stdout.split(b":")[1].strip()
                    if details.startswith(b"ELF "):
                        yield bin_path

    @classmethod
    def _get_potential_binaries(cls, rehost_type):
        if rehost_type == "HTTP":
            return POTENTIAL_HTTPSERV
        elif rehost_type == "UPNP":
            return POTENTIAL_UPNPSERV
        elif rehost_type == "DNS":
            return POTENTIAL_DNSSERV
        elif rehost_type == "DHCP":
            return POTENTIAL_DHCPSERV
        return "UNKNOWN"


def _parse_args():
    parser = ArgumentParser(description="Service Analyzer")
    parser.add_argument("-fs", "--fs_path", help="Filesystem path")
    parser.add_argument("-c", "--corpus_path", help="Corpus path")
    parser.add_argument(
        "-t",
        "--rehost_type",
        nargs="+",
        choices=["HTTP", "UPNP", "DNS", "DHCP"],
        help="Rehost type",
    )
    return parser.parse_args()


def _run_corpus(corpus_path, rehost_types):
    from init_analysis.collect import iter_workspaces
    results = {}
    for vendor, image, workspace in iter_workspaces(corpus_path):
        fs_path = os.path.join(workspace, "fs")
        if not os.path.isdir(fs_path):
            continue
        result = _run_one(fs_path, rehost_types)
        results[f"{vendor}/{image}"] = result
    return results


def _run_one(fs_path, rehost_types):
    result = dict()
    for rehost_type in rehost_types:
        binaries = []
        for binary in GHServiceAnalyzer.find_binary(fs_path, rehost_type):
            binary_rel_path = os.path.relpath(binary, fs_path) if binary else None
            binaries.append(binary_rel_path)
        result[rehost_type] = binaries
    # json.dump(result, sys.stdout, indent=4)
    return result


def main():
    """Main function"""
    args = _parse_args()
    fs_path = args.fs_path
    corpus_path = args.corpus_path
    if fs_path and corpus_path:
        print("Cannot specify both fs_path and corpus_path", file=sys.stderr)
        exit(1)
    if not fs_path and not corpus_path:
        print("Must specify either fs_path or corpus_path", file=sys.stderr)
        exit(1)

    if not args.rehost_type:
        rehost_types = ["HTTP", "UPNP", "DNS"] # Greenhouse paper does not mention DHCP
    else:
        rehost_types = args.rehost_type

    if fs_path:
        result = _run_one(fs_path, rehost_types)
        print(json.dumps(result, indent=4))
    else:
        results = _run_corpus(corpus_path, rehost_types)
        print(json.dumps(results, indent=4))
        for image, type_map in results.items():
            for binaries in type_map.values():
                for binary in binaries:
                    print(image+",/"+binary)


if __name__ == "__main__":
    main()
