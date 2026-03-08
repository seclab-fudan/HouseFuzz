#!python
import sys
import os
import json
from argparse import ArgumentParser

import tarfile


def iter_workspaces(out_folder_path):
    """Iterate over workspaces"""
    guess_out_folder = os.path.join(out_folder_path, "init_analysis")
    if os.path.isdir(guess_out_folder):
        out_folder_path = guess_out_folder

    for vendor in os.listdir(out_folder_path):
        dir_path = os.path.join(out_folder_path, vendor)
        if not os.path.isdir(dir_path):
            continue
        for image in os.listdir(dir_path):
            inp_file_path = os.path.join(dir_path, image)
            if not os.path.isdir(inp_file_path):
                continue
            workspace = os.path.join(out_folder_path, vendor, image)
            yield vendor, image, workspace


def examine_workspace(workspace):
    """Examine workspace"""
    res = {}
    if not os.path.isdir(workspace):
        res["status"] = "Uninitialized"
        return res

    logs_tar_path = os.path.join(workspace, "logs.tar")
    if not os.path.exists(logs_tar_path):
        res["status"] = "NoLog"
        return res
    try:
        tar = tarfile.open(logs_tar_path, "r")
    except tarfile.ReadError:
        res["status"] = "NoLog"
        return res

    try:
        bindings_item = tar.getmember("bindings.json")
    except KeyError:
        res["status"] = "NoBinding"
        return res
    bindings = json.loads(tar.extractfile(bindings_item).read().decode("utf-8"))
    if not bindings or not bindings.get("remote") and not bindings.get("local"):
        res["status"] = "NoBinding"
        return res

    try:
        services_item = tar.getmember("services.json")
    except KeyError:
        res["status"] = "NoService"
        return res
    services = json.loads(tar.extractfile(services_item).read().decode("utf-8"))
    if not services:
        res["status"] = "NoService"
        return res

    daemon_progs = set()
    try:
        ps_aux_item = tar.getmember("ps_aux.log")
        f = tar.extractfile(ps_aux_item)
        for line in f:
            line = line.decode("utf-8")
            idx = line.find("/qemu-")
            if idx == -1:
                continue
            line = line[idx:]
            elements = line.strip().split()
            i = 0
            while i < len(elements):
                if "qemu-" in elements[i] or elements[i] in [
                    "-execve",
                    "-ponly",
                    "-hackbind",
                    "-hackproc",
                    "-hacksysinfo",
                    "-hackhouse",
                    "-singlestep",
                    "-strace",
                    "-seed",
                    "-version",
                ]:
                    i += 1
                elif elements[i] in [
                    "-0",
                    "-pid",
                    "-g",
                    "-L",
                    "-s",
                    "-cpu",
                    "-E",
                    "-U",
                    "-r",
                    "-B",
                    "-R",
                    "-d",
                    "-dfilter",
                    "-D",
                    "-p",
                    "-tracename",
                    "-trace",
                ]:
                    i += 2
                else:
                    daemon_progs.add(elements[i])
                    break
    except KeyError:
        pass

    tar.close()

    daemon_services = []

    known_daemons = ["http", "upnp", "dns"]

    for service in services:
        if any(prog in service["netbind_cmd"] for prog in daemon_progs) or any(
            known_daemon in service["netbind_cmd"] for known_daemon in known_daemons
        ):
            daemon_services.append(service)
        else:
            # print(f"Warning: {service['netbind_cmd']} not in {daemon_progs}")
            pass

    has_http = False
    for prog_bindings in bindings.get("remote", {}).values():
        for binding in prog_bindings:
            if "port" in binding and binding["port"] == "80":
                has_http = True
                break
    if not has_http:
        has_http = any("http" in prog for prog in daemon_progs)

    if not daemon_services:
        res["status"] = "NoDaemon"
        return res

    res["status"] = "Success"
    if not has_http:
        res["status"] = "NoHTTP"
    res["services"] = daemon_services

    return res


def _parse_args():
    parser = ArgumentParser(description="Collect init analysis results")
    parser.add_argument("out_folder", help="Output folder")
    parser.add_argument("-o", "--output", help="Output file")
    return parser.parse_args()


def _main():
    args = _parse_args()
    out_folder_path = os.path.realpath(args.out_folder)
    guess_out_folder = os.path.join(out_folder_path, "init_analysis")
    if os.path.isdir(guess_out_folder):
        out_folder_path = guess_out_folder

    statistics = {}
    results = {}
    for vendor, image, workspace in iter_workspaces(out_folder_path):
        res = examine_workspace(workspace)
        results[f"{vendor}/{image}"] = res
        statistics.setdefault(res["status"], 0)
        statistics[res["status"]] += 1
        # print(f"{vendor}/{image}:", json.dumps(res, indent=2))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    else:
        json.dump(results, sys.stdout, indent=2)
    print("\nStatistics:", json.dumps(statistics, indent=2))

    if False:
        # Printing entry binaries
        for image, image_result in results.items():
            visited = set()
            services = image_result.get("services")
            if not services:
                continue
            for service in services:
                entry_cmd = service["entry_cmd"]
                bin_path = entry_cmd.split()[0]
                if bin_path in visited:
                    continue
                visited.add(bin_path)

                print(image, bin_path)


if __name__ == "__main__":
    _main()
