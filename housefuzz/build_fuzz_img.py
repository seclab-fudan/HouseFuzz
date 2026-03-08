#!python
"""
This script is used to build a fuzzing image based on a Greenhouse fuzzing image
"""
import sys
import os
from argparse import ArgumentParser
from subprocess import check_output, run, PIPE
import logging
import tempfile
import shutil
import tarfile
import json
import shlex
import re
import time
from difflib import SequenceMatcher

import docker
from docker.errors import ImageNotFound

sys.path.append(os.path.join(os.path.dirname(__file__), "../service-analyzer"))
# pylint: disable=wrong-import-position
from init_analysis.qemu_runner import PlanterUtils


FUZZING_SCRIPT = """#!/fuzz_bins/utils/sh

CMD={command}
PROG={prog}
HF_NO_CFG=${{HF_NO_CFG:-0}}
HF_NO_DEP=${{HF_NO_DEP:-0}}

export PATH=/fuzz_bins/utils:$PATH
export QEMU_SET_ENV="PATH=$PATH,LD_PRELOAD=$LD_PRELOAD"
unset LD_PRELOAD
mkdir -p /afltmp
mkdir -p /aflfix

/greenhouse/busybox rm -f aflcrash.log
/greenhouse/busybox rm -f afl.log
/greenhouse/busybox rm -f aflserver.log
/greenhouse/busybox rm -f cmdlist.txt
/greenhouse/busybox rm -f http_input.txt
/greenhouse/busybox rm -f move_file.txt
/greenhouse/busybox rm -f httpd_pc.txt
/greenhouse/busybox rm -f qemu_crash.log

# /run_setup.sh

# launch the fuzzer
echo "[Fuzz] Start Fuzzing..."
# export AFL_DEBUG=1
export AFL_MAIN_BIN=1
export AFL_ENTRYPOINT={entrypoint:#x}
export LD_BIND_LAZY=1
export AFL_NO_AFFINITY=1
# export AFL_QEMU_EXTRA_ARGS="-d strace -D /qemu_strace.log"

export FUZZING_TIMEOUT=24h
export INTERFACE_PORT={port}


if [ $HF_NO_DEP -ne 0 ]; then
    PROG=httpd
    exec /fuzz_bins/utils/timeout -s INT $FUZZING_TIMEOUT /fuzz_bins/bin/afl-fuzz -t 1000 -u -Q -q -i /scratch/json_seeds -a /scratch/api.dict -x /scratch/dict.json -o /scratch/output -P $PROG -- $CMD
elif [ $HF_NO_CFG -eq 0 ]; then
    exec /fuzz_bins/utils/timeout -s INT $FUZZING_TIMEOUT /fuzz_bins/bin/afl-fuzz -t 1000 -u -Q -i /scratch/json_seeds -a /scratch/api.dict -x /scratch/dict.json -o /scratch/output -P $PROG -- $CMD
else
    exec /fuzz_bins/utils/timeout -s INT $FUZZING_TIMEOUT /fuzz_bins/bin/afl-fuzz -t 1000 -u -Q -r -i /scratch/raw_seeds -a /scratch/api.dict -x /fuzz/dictionary -o /scratch/output -P $PROG -- $CMD
fi
while true; do sleep 60; done
"""

RUN_SCRIPT = """#!/bin/sh

cd $(dirname $0)

# Configurations
ROUND=${{ROUND:-1}}

# Only one configuration is allowed. TODO: add a check
HF_NO_TDG_OFFLINE=${{HF_NO_TDG_OFFLINE:-0}}
HF_NO_CFG=${{HF_NO_CFG:-0}}
HF_NO_DEP=${{HF_NO_DEP:-0}}
GH_YES=${{GH_YES:-0}}

HF_RESUME=${{HF_RESUME:-0}}

# Apply configurations
SCRATCH_BASE={scratch_dir}
SCRATCH_DIR="${{SCRATCH_BASE}}_${{ROUND}}"

if [ $HF_RESUME -eq 0 ]; then
    rm -rf "$SCRATCH_DIR"
    cp -r "$SCRATCH_BASE" "$SCRATCH_DIR"
else
    cp -r "$SCRATCH_BASE/*" "$SCRATCH_DIR"
    BINCOV_DATA="$SCRATCH_DIR/output/default/bincov_data"
    mv $BINCOV_DATA ${{BINCOV_DATA}}.bak
fi

# copy dictionary
if [ $HF_NO_DEP -ne 0 ]; then
    cp $SCRATCH_BASE/api_no_dep.dict $SCRATCH_DIR/api.dict
    cp $SCRATCH_BASE/dict_no_dep.json $SCRATCH_DIR/dict.json
elif [ $HF_NO_TDG_OFFLINE -eq 0 ]; then
    cp $SCRATCH_BASE/api_non_empty.dict $SCRATCH_DIR/api.dict
    cp $SCRATCH_BASE/dict_non_empty.json $SCRATCH_DIR/dict.json
else
    cp $SCRATCH_BASE/api_empty.dict $SCRATCH_DIR/api.dict
    cp $SCRATCH_BASE/dict_empty.json $SCRATCH_DIR/dict.json
fi

export DOCKER_HOST={docker_host}
if [ $GH_YES -eq 0 ]; then
    # container=$(docker run --rm -dit --cpus=1 --privileged -e "INTERFACE_PORT={port}" -e "HF_NO_CFG=$HF_NO_CFG" -e "HF_NO_DEP=$HF_NO_DEP" -e "AFL_AUTORESUME=$HF_RESUME" -v $SCRATCH_DIR:/scratch {hf_image} /housefuzz.sh)
    container=$(docker run --rm -dit --cpus=1 --privileged -e "INTERFACE_PORT={port}" -e "HF_NO_CFG=$HF_NO_CFG" -e "HF_NO_DEP=$HF_NO_DEP" -e "AFL_AUTORESUME=$HF_RESUME" {hf_image} /housefuzz.sh)
    echo $container
else
    container=$(docker run --rm -dit --cpus=1 --privileged -e "INTERFACE_PORT={port}" -e "AFL_AUTORESUME=$HF_RESUME" -v $SCRATCH_DIR:/scratch {gh_image} /fuzz.sh)
    echo $container
fi
echo "Fuzzer started at $container.. Starting background.sh"
if docker exec $container /greenhouse/busybox ls /scratch > /dev/null 2>&1; then
    echo "/scratch exists, delete it"
    docker exec $container /greenhouse/busybox rm -rf /scratch
else
    echo "/scratch doesn't exist"
fi
docker cp $SCRATCH_DIR $container:/scratch
docker exec -dit $container /background.sh
echo "Attach to $container"
docker attach $container
chown -R `stat -c "%u:%g" $SCRATCH_DIR` $SCRATCH_DIR
"""

REBUILD_SCRIPT = """#!/bin/sh
cd $(dirname $0) && docker build -t {image} .
"""

HF_DOCKERFILE = """FROM {image}
        
COPY afl-fuzz /fuzz_bins/bin/afl-fuzz
COPY afl-qemu-trace /qemu-{arch}-static
COPY afl-qemu-trace /fuzz_bins/bin/afl-qemu-trace
COPY grammar /fuzz_bins/grammar

COPY send_ok /fuzz_bins/bin/send_ok
COPY libnvram_fuzz.so /lib/libnvram_fuzz.so
COPY guidance.json /guidance.json

COPY delete.sh /delete.sh
COPY all_nvram.ini /all_nvram.ini
COPY scratch /scratch
COPY background.sh /background.sh
COPY housefuzz.sh /housefuzz.sh


RUN ["/greenhouse/busybox", "chmod", "a+x", "/fuzz_bins/bin/afl-fuzz"]
RUN ["/greenhouse/busybox", "chmod", "a+x", "/fuzz_bins/bin/afl-qemu-trace"]
RUN ["/greenhouse/busybox", "chmod", "a+x", "/fuzz_bins/bin/send_ok"]
RUN ["/greenhouse/busybox", "chmod", "a+x", "/delete.sh"]
RUN ["/greenhouse/busybox", "chmod", "a+x", "/housefuzz.sh"]
RUN ["/greenhouse/busybox", "chmod", "a+x", "/background.sh"]

# RUN /greenhouse/busybox chmod a+x /fuzz_bins/bin/afl-fuzz \   
#     /fuzz_bins/bin/afl-qemu-trace \
#     /fuzz_bins/bin/send_ok \
#     /delete.sh \
#     /housefuzz.sh \
#     /background.sh
"""


class FuzzImageBuilder:
    """Build fuzzing image

    The builder requres three parts of inputs:
    base: Base image, which contains fuzzing environment and target file system
    af_path: The path to pre_built binaries and initial seeds
    """

    def __init__(self, base, af_path, outdir, gh_fb_path, log=None):
        self._base = base
        self._client = docker.from_env()
        self._af_path = af_path
        self._gh_fb_path = gh_fb_path

        self._outdir = outdir
        os.makedirs(self._outdir, exist_ok=True)
        if log:
            self.log = log
        else:
            self.log = logging.getLogger(__name__)
            self.log.addHandler(logging.StreamHandler())
            self.log.setLevel(logging.DEBUG)

    def build_base(self, base, fs_path):
        """Build base image without relying on Greenhouse fuzzing image"""
        workdir = os.path.join(self._outdir, "base")
        os.makedirs(workdir, exist_ok=True)

        tar_cmd = [
            "tar",
            "-x",
            "-f",
            fs_path,
            "-C",
            workdir,
            "--no-same-permissions",
            "--keep-directory-symlink",
        ]
        if os.path.exists(os.path.join(workdir, "fs")):
            shutil.rmtree(os.path.join(workdir, "fs"))

        ret = run(tar_cmd, check=False, stdout=PIPE, stderr=PIPE)
        # print(ret)

        src_fuzz_bins = os.path.join(self._af_path, "fuzz_bins")
        dst_fuzz_bins = os.path.join(workdir, "fuzz_bins")
        if os.path.exists(dst_fuzz_bins):
            shutil.rmtree(dst_fuzz_bins)
        shutil.copytree(src_fuzz_bins, dst_fuzz_bins)

        with open(os.path.join(workdir, "Dockerfile"), "w", encoding="utf-8") as f:
            f.write("FROM scratch\n")
            f.write("COPY fs/ /\n")
            f.write("COPY fuzz_bins /fuzz_bins\n")
            f.write("WORKDIR /scratch\n")
            f.write("ENTRYPOINT /fuzz_bins/utils/sh\n")

        self.log.info("Building Docker image %s at %s", base, workdir)
        image, _json_log = self._client.images.build(
            path=workdir,
            tag=base,
            rm=True,
            nocache=True,
        )
        self.log.info("Base image built: %s", base)

        return image

    def build(self, target, srv_path, tdg_path, no_dep_tdg_path, from_fs):
        """Build fuzzing image

        :param srv_path: Path to service information -- logs.tar generated by init_analysis
        :param tdg_path: Path to TDG directory
        :param no_dep_tdg_path: Path to TDG directory used for no_dep mode
        :param from_fs: Use fs instead of greenhouse image
        """

        image = self._get_base_image()
        if not image:
            self.log.error("Cannot find base image: %s", self._base)
            return False

        client = self._client

        container = self._client.containers.run(
            image, command="/greenhouse/busybox sh", detach=True, tty=True, privileged=True
        )

        try:
            if from_fs:
                self.build_without_gh(target, image, container, srv_path, tdg_path, no_dep_tdg_path)
            else:
                self.build_with_gh(target, image, container, srv_path, tdg_path, no_dep_tdg_path)
        finally:
            container.stop()
            container.remove()

    def build_without_gh(self, target, image, container, srv_path, tdg_path, no_dep_tdg_path):
        """Build fuzzing image solely based on HouseFuzz service information"""
        services = self._get_service_info(srv_path)
        if not services:
            self.log.error("Cannot find service information")
            return

        cmd_visited = set()
        for service in services:
            cmd = service.get("netbind_cmd")
            if not cmd:
                self.log.error("Cannot find netbind_cmd in service")
                continue

            if cmd in cmd_visited:
                continue
            cmd_visited.add(cmd)

            self.log.info("Building fuzzing image for service: %s", service)

            self.log.info("Use HouseFuzz command: %s", cmd)
            dep_cmds = service.get("dep_cmds", [])
            self.log.info("Use HouseFuzz dependency commands: %s", dep_cmds)
            ports = [
                binding["port"]
                for binding in service["remote_bindings"]
                if "port" in binding
            ]
            self.log.info("Use ports: %s", ports)
            for port in ports:
                self.build_one(target, container, cmd, port, dep_cmds, tdg_path, no_dep_tdg_path)

    def build_with_gh(self, target, image, container, srv_path, tdg_path, no_dep_tdg_path):
        """Build fuzzing image based on greenhouse fuzzing image"""
        self.log.info("Reading Greenhouse command")
        try:
            print(image)
            script = self._client.containers.run(image, ["/greenhouse/busybox", "cat", "/qemu_run.sh"])
        except Exception as e:
            print(f"exception found: {e}")
            exit()
        cat_res = [line for line in script.decode("utf-8").split("\n") if line.strip()]
        if cat_res:
            cmd = cat_res[-1]
            self.log.info("Using GreenHouse command: %s", cmd)
        else:
            self.log.error("Cannot find Greenhouse command")
            cmd = None

        services = self._get_service_info(srv_path)
        ports = []
        if services:
            matched_service = self._find_matched_service(services, cmd)
            if matched_service:
                self.log.info("Matched service: %s", matched_service)
                ports = [
                    binding["port"]
                    for binding in matched_service["remote_bindings"]
                    if "port" in binding
                ]
                self.log.info("Using ports %s", ports)
        if not ports:
            ports = ["80"]
            self.log.info("Using default ports %s", ports)
        dep_cmds = self._load_gh_dep_cmds(container)
        print('-------------------------------------')
        self.log.info("Use Greenhouse dependency commands: %s", dep_cmds)

        for port in ports:
            self.build_one(target, container, cmd, port, dep_cmds, tdg_path, no_dep_tdg_path)

    def build_one(self, target, container, cmd, port, dep_cmds, tdg_path, no_dep_tdg_path):
        """Build fuzzing image for specified service interface"""

        self.log.info("Building fuzzing image for cmd %s, port %s", cmd, port)
        target_bin = cmd.split()[0]

        self.log.info("Inferring arch and clibc")
        arch, clibc = self._get_arch_config(container, target_bin)
        self.log.info("Bin: %s, Arch: %s, CLibc: %s", target_bin, arch, clibc)

        self._infer_fork_setup(container, dep_cmds, arch)
        fork_addr = self._infer_fork_address(container, cmd, port, arch)
        if not fork_addr:
            self.log.error("Cannot find fork server address for port %s", port)
            return None

        instance_outdir = os.path.join(self._outdir, f"p{port}")
        os.makedirs(instance_outdir, exist_ok=True)
        self._copy_hf_bins(instance_outdir, arch, clibc)
        self.log.info("Output directory: %s", instance_outdir)
        self._copy_hf_script_confs(
            container,
            instance_outdir,
            cmd,
            fork_addr,
            port,
            dep_cmds,
            tdg_path,
            no_dep_tdg_path
        )

        # Build docker
        self._build_hf_image(
            self._base, target + f"_p{port}", instance_outdir, arch, port
        )

    def _get_service_info(self, tar_path):
        if not tar_path:
            return None
        with tarfile.open(tar_path, mode="r") as tar:
            try:
                services = json.load(tar.extractfile("services.json"))
            except KeyError:
                services = {}

            try:
                bindings = json.load(tar.extractfile("bindings.json"))
            except KeyError:
                bindings = {}

        self.log.info("#Services=%d", len(services))
        self.log.info("#Bindings=%d", len(bindings))
        return services

    def _find_matched_service(self, services, gh_cmd):

        # Find service with matched command
        max_similarity = 0
        matched_service = None
        for service in services:
            cmd = service["netbind_cmd"]
            bin_name = cmd.split()[0]
            gh_bin_name = gh_cmd.split()[0]
            if bin_name == gh_bin_name or os.path.basename(
                bin_name
            ) == os.path.basename(gh_bin_name):
                diff_ratio = SequenceMatcher(None, cmd, gh_cmd).ratio()
                if diff_ratio > max_similarity:
                    max_similarity = diff_ratio
                    matched_service = service

        if not matched_service:
            return None

        return matched_service

    def _infer_fork_setup(self, container, dep_cmds, arch):
        src_path = os.path.join(self._gh_fb_path, f"qemu/afl-qemu-trace-{arch}")
        dst_path = "/fuzz_bins/bin/afl-qemu-trace"
        self._copy_to(container, src_path, dst_path)

        tmp_background = ""
        if dep_cmds:
            for dep_cmd in dep_cmds:
                tmp_background += self._get_qemu_cmd(dep_cmd) + ";"
        if tmp_background:
            command = ["/fuzz_bins/utils/sh", "-c", tmp_background]
            self.log.info("Running background commands: %s", command)
            _, _stream = container.exec_run(
                cmd=command,
                stream=True,
            )
            # for chunk in _stream:
            #     self.log.debug(chunk)

    def _infer_fork_address(self, container, cmd, port, arch):
        self.log.info("Infering fork server address")
        command = [
            "/fuzz_bins/utils/sh",
            "-c",
            '/fuzz_bins/utils/timeout -s KILL $DRYRUN_TIMEOUT /fuzz_bins/bin/afl-qemu-trace -hookhack -hackbind -hackproc -execve "/fuzz_bins/bin/afl-qemu-trace -hookhack -hackbind -hackproc" -- $CMD 2>&1',
        ]
        self.log.info("Trying port %s", port)
        time_out = 30
        _, stream = container.exec_run(
            cmd=command,
            stream=True,
            environment={
                "GH_DRYRUN": "1",
                "INTERFACE_PORT": str(port),
                "CMD": cmd,
                "DRYRUN_TIMEOUT": str(time_out),
            },
        )
        addr = None
        
        for chunk in stream:
            # self.log.debug(chunk.decode("utf-8"))
            mat = re.search(rb"return addr:\s*(?P<addr>0x[0-9a-fA-F]+)", chunk)
            if mat:
                addr = int(mat.group("addr"), 16)
                if arch.startswith("mips"):
                    addr -= 4
                break
        if addr:
            self.log.info("Fork server address: %#x for port %s", addr, port)
            return addr
        else:
            self.log.error("Cannot find fork server address for port %s", port)
            return None

    def _build_hf_image(self, image, target_image, build_dir, arch, port):
        dockerfile = HF_DOCKERFILE.format(image=image, arch=arch)
        with open(os.path.join(build_dir, "Dockerfile"), "w", encoding="utf-8") as f:
            f.write(dockerfile)

        docker_ignore = "scratch_*"
        with open(os.path.join(build_dir, ".dockerignore"), "w", encoding="utf-8") as f:
            f.write(docker_ignore)
        self.log.info("Building Docker image %s at %s", target_image, build_dir)
        with open(
            os.path.join(build_dir, "docker-compose.yml"), "w", encoding="utf-8"
        ) as f:
            f.write("version: '3'\n")
            f.write("services:\n")
            f.write(f"    {target_image}:\n")
            f.write(f"        build: {build_dir}\n")
            f.write("        privileged: true\n")
            f.write("        tty: true\n")
            f.write("        stdin_open: true\n")

        scratch_dir = os.path.realpath(os.path.join(build_dir, "scratch"))
        os.makedirs(scratch_dir, exist_ok=True)

        with open(os.path.join(build_dir, "run.sh"), "w", encoding="utf-8") as f:
            f.write(
                RUN_SCRIPT.format(
                    scratch_dir=scratch_dir,
                    docker_host=os.getenv("DOCKER_HOST", ""),
                    hf_image=target_image,
                    gh_image=image,
                    port=port,
                )
            )
        os.chmod(os.path.join(build_dir, "run.sh"), 0o755)

        with open(os.path.join(build_dir, "rebuild.sh"), "w", encoding="utf-8") as f:
            f.write(REBUILD_SCRIPT.format(image=target_image))
        os.chmod(os.path.join(build_dir, "rebuild.sh"), 0o755)

        try:
            image, _json_log = self._client.images.build(
                path=build_dir,
                tag=target_image,
                rm=True,
                nocache=True,
            )
        except Exception as e:
            print(f"exception found: {e}")
            exit()
        self.log.info("Image built: %s", target_image)

    def _copy_hf_bins(self, output, arch, clibc):
        # afl-fuzz
        self.log.info("Copying binary files to the container")
        afl_fuzz_path = os.path.join(self._af_path, "fuzz_bins/bin/afl-fuzz")
        shutil.copyfile(afl_fuzz_path, os.path.join(output, "afl-fuzz"))

        # qemu
        shutil.copyfile(
            os.path.join(self._af_path, f"fuzz_bins/qemu/afl-qemu-trace-{arch}"),
            os.path.join(output, "afl-qemu-trace"),
        )

        # send_ok
        shutil.copy(
            os.path.join(self._af_path, "send_ok"), os.path.join(output, "send_ok")
        )

        # libnvram_fuzz.so
        libnvram_fuzz_path = os.path.join(
            self._af_path, f"libs/{arch}/{clibc}/libnvram-fuzz.so"
        )
        shutil.copy(libnvram_fuzz_path, os.path.join(output, "libnvram_fuzz.so"))

        # grammar mutators
        grammar_mutator_path = os.path.join(output, "grammar")
        if os.path.exists(grammar_mutator_path):
            shutil.rmtree(grammar_mutator_path)
        shutil.copytree(
            os.path.join(self._af_path, "fuzz_bins/grammar"),
            grammar_mutator_path,
        )

    def _copy_hf_script_confs(
        self,
        container,
        output,
        command,
        fork_addr,
        port,
        dep_cmds,
        tdg_path,
        no_dep_tdg_path
    ):
        # afl-fuzz
        self.log.info("Copying script/configuration files to the container")

        # all_nvram.ini
        self._setup_all_nvram(container, os.path.join(output, "all_nvram.ini"))

        # guidance.json
        guidance_path = os.path.join(output, "guidance.json")
        with open(guidance_path, "wb") as f:
            f.write(b"{}")

        # delete.sh
        delete_sh_path = os.path.join(self._af_path, "delete.sh")
        shutil.copy(delete_sh_path, os.path.join(output, "delete.sh"))

        scratch_dir = os.path.join(output, "scratch")
        os.makedirs(scratch_dir, exist_ok=True)

        prog = os.path.basename(command.split()[0])
        with open(os.path.join(scratch_dir, "dict_empty.json"), "w", encoding='utf-8') as f:
            json.dump(
                {
                    prog: [
                        {
                            "possible_name": ["index.htm"],
                            "possible_args": [
                                {
                                    "key": "wlan_acl_num",
                                    "call_addr": 378312,
                                    "source_func": 63684,
                                    "value": [],
                                    "type": "int",
                                    "encode": "normal",
                                }
                            ],
                            "possible_values": ["resp_type", "%>"],
                            "possible_type": ["normal"],
                        }
                    ]
                },
                f,
            )

        with open(os.path.join(scratch_dir, "api_empty.dict"), "w", encoding='utf-8') as f:
            json.dump(
                {
                    "perfix": ["/"],
                    "name": ["xxx.cgi"],
                    "full": ["/xxx.cgi"],
                    "headers": [{"name": "BASE", "value": []}],
                },
                f,
            )

        api_dict_path = os.path.join(tdg_path, "api.dict")
        if os.path.exists(api_dict_path):
            shutil.copy(api_dict_path, os.path.join(scratch_dir, "api_non_empty.dict"))
            # shutil.copy(api_dict_path, os.path.join(scratch_dir, "api.dict"))
        else:
            self.log.warning("Cannot find api.dict in %s. Using empty one", tdg_path)

        dict_json_path = os.path.join(tdg_path, "dict.json")
        if os.path.exists(dict_json_path):
            shutil.copy(
                dict_json_path, os.path.join(scratch_dir, "dict_non_empty.json")
            )
        else:
            self.log.warning("Cannot find dict.json in %s.", tdg_path)

        no_dep_api_dict_path = os.path.join(no_dep_tdg_path, "cfg_only_api.dict")
        if os.path.exists(no_dep_api_dict_path):
            shutil.copy(no_dep_api_dict_path, os.path.join(scratch_dir, "api_no_dep.dict"))
        else:
            self.log.warning(
                "Cannot find cfg_only_api.dict in %s.", no_dep_tdg_path
            )
        
        no_dep_dict_json_path = os.path.join(no_dep_tdg_path, "cfg_only_dict.json")
        if os.path.exists(no_dep_tdg_path):
            shutil.copy(no_dep_dict_json_path, os.path.join(scratch_dir, "dict_no_dep.json"))
        else:
            self.log.warning(
                "Cannot find cfg_only_dict.json in %s.", no_dep_tdg_path
            )

        # json_seeds
        json_seeds_dir = os.path.join(scratch_dir, "json_seeds")
        if os.path.exists(json_seeds_dir):
            shutil.rmtree(json_seeds_dir)
        shutil.copytree(
            os.path.join(self._af_path, "json_seeds"),
            json_seeds_dir,
        )

        raw_seeds_dir = os.path.join(scratch_dir, "raw_seeds")
        if os.path.exists(raw_seeds_dir):
            shutil.rmtree(raw_seeds_dir)
        shutil.copytree(
            os.path.join(self._af_path, "raw_seeds"),
            raw_seeds_dir,
        )

        # housefuzz.sh
        with open(os.path.join(output, "housefuzz.sh"), "wb") as f:
            # TODO: Add command and entrypoint
            qupte_cmd = shlex.quote(command)
            f.write(
                FUZZING_SCRIPT.format(
                    command=qupte_cmd, prog=prog, entrypoint=fork_addr, port=port
                ).encode()
            )

        # background.sh
        visited = set()
        with open(os.path.join(output, "background.sh"), "w", encoding="utf-8") as f:
            f.write("#!/fuzz_bins/utils/sh\n")
            f.write("/fuzz_bins/utils/sleep 5\n")
            for dep_cmd in dep_cmds:
                if dep_cmd in visited:
                    continue
                visited.add(dep_cmd)
                f.write(self._get_qemu_cmd(dep_cmd))
                f.write("\n")
            f.write("/fuzz_bins/utils/sleep 3\n")
            f.write("/fuzz_bins/bin/send_ok\n")
            f.write("while true; do /fuzz_bins/utils/sleep 1000; done\n")

    def _load_gh_dep_cmds(self, container):
        # Load Greenhouse dependency commands
        _, stream = container.exec_run(["/greenhouse/busybox", "cat", "/run_background.sh"], stream=True)
        dep_cmds = []
        buffer = ""
        for chunk in stream:
            buffer += chunk.decode("utf-8")
        for line in buffer.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                continue
            dep_cmds.append(line)
        return dep_cmds

    def _setup_all_nvram(self, container, nvram_path):

        tmp_tar = tempfile.mktemp(suffix=".tar", prefix="tmp_tar")
        stream, _ = container.get_archive("/gh_nvram")
        with open(tmp_tar, "wb") as f:
            for chunk in stream:
                f.write(chunk)
        tar = tarfile.open(tmp_tar, mode="r")

        output_file = nvram_path
        with open(output_file, "wb") as outfile:
            for tarinfo in tar:
                if tarinfo.isfile():
                    with tar.extractfile(tarinfo) as infile:
                        value = infile.read().strip()  # Value

                    key = os.path.basename(tarinfo.name).encode()
                    outfile.write(key)
                    outfile.write(b"=")
                    outfile.write(value)
                    outfile.write(b"\n")

        os.remove(tmp_tar)

    def _copy_to(self, container, src, dst):
        self.log.info("Copying %s to %s:%s", src, container.name, dst)
        tmp_tar = tempfile.mktemp(suffix=".tar", prefix="tmp_tar")
        tar = tarfile.open(tmp_tar, mode="w")
        try:
            target_dir = "."
            try:
                if os.path.isabs(dst):
                    dst = dst[1:]
                    target_dir = "/"
                tar.add(src, arcname=dst)
            finally:
                tar.close()

            data = open(tmp_tar, "rb").read()
            container.put_archive(target_dir, data)
        finally:
            os.remove(tmp_tar)

    def _get_qemu_cmd(self, cmd):
        return f'/fuzz_bins/bin/afl-qemu-trace -hackbind -hackproc -E AFL_QEMU_CHILD_SETUP=1 -execve "/fuzz_bins/bin/afl-qemu-trace -hackbind -hackproc -E AFL_QEMU_CHILD_SETUP=1" {cmd}'

    def _get_base_image(self):
        try:
            image = self._client.images.get(self._base)
            return image
        except ImageNotFound:
            return None

    def _get_arch_config(self, container, bin_path):
        stream, _ = container.get_archive(bin_path)
        tmp_dir = tempfile.mkdtemp()
        tmp_archive = os.path.join(tmp_dir, "archive.tar")
        with open(tmp_archive, "wb") as f:
            for chunk in stream:
                f.write(chunk)

        shutil.unpack_archive(tmp_archive, tmp_dir)
        output = check_output(
            ["file", os.path.join(tmp_dir, os.path.basename(bin_path))], stderr=PIPE
        )
        arch = PlanterUtils.get_arch_from_file_output(output)
        clibc = PlanterUtils.get_clib_from_file_output(output)
        return arch, clibc


def _parse_args():
    parser = ArgumentParser()
    parser.add_argument("-t", "--target", help="Target image name", required=True)
    parser.add_argument("-b", "--base", help="Base image name", required=True)
    parser.add_argument(
        "-o",
        "--outdir",
        help="Output directory",
        required=True,
    )
    parser.add_argument(
        "--af-path",
        default=os.path.join(os.path.dirname(__file__), "artifacts"),
        help="Artifacts path",
        required=True,
    )
    parser.add_argument("--gh-fb-path", default="", help="Path to greenhouse fuzz_bin", required=True)
    parser.add_argument(
        "--srv-path", default="", help="Path to service information", required=True
    )
    parser.add_argument(
        "--tdg-path", default="", help="Path to TDG information", required=True
    )
    parser.add_argument(
        "--no-dep-tdg-path", default="", help="Path to TDG information", required=False
    )
    parser.add_argument(
        "--from-fs",
        default="",
        help="File system tar file path",
    )

    return parser.parse_args()


def _main():
    args = _parse_args()
    builder = FuzzImageBuilder(args.base, args.af_path, args.outdir, args.gh_fb_path)
    if args.from_fs:
        from_fs = True
        builder.build_base(args.base, args.from_fs)
    else:
        from_fs = False
    builder.build(args.target, args.srv_path, args.tdg_path, args.no_dep_tdg_path, from_fs)


if __name__ == "__main__":
    _main()
