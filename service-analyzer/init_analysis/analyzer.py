"""
Analyze Init Program to extract service information
"""

import os
import logging
import json
import shutil
import re

import tarfile

from .utils import Files
from .extractor import Extractor
from .scanners import InitScanner
from .qemu_runner import QemuRunner, QemuRunStatus, RunEnvSetup
from .trace_parser import TraceParser
from .trace_analyzer import TraceAnalyzer, TranslateBlock
from .patcher import Patcher, PatchHistory


class InitAnalyzer:
    """Analyze Init Program to extract service information"""

    def __init__(self, workspace, image_path, artifact_path) -> None:
        self._workspace = workspace
        self._image_path = image_path
        self._fs_path = os.path.join(self._workspace, "fs")
        self._artifact_path = artifact_path

        # Runtime variables
        self._init_cmd = None
        self._init_program = (
            None  # relative path to the init program starting from fs_path
        )
        self._patchers = {}
        self._patch_history = None

        self.log = logging.getLogger(__name__)
        self.log.setLevel(logging.DEBUG)
        self.log.addHandler(logging.StreamHandler())

        log_path = os.path.join(self._workspace, "analyzer_output.log")
        if os.path.exists(log_path):
            os.remove(log_path)

        self.log.addHandler(logging.FileHandler(log_path))
        self._services = []

    @property
    def services(self):
        """Inferre (network) services"""
        return self._services

    def get_patcher(self, bin_rel_path):
        """Patcher for binary file"""
        if not bin_rel_path:
            return None
        if bin_rel_path.startswith("/"):
            bin_rel_path = bin_rel_path[1:]
        patcher = self._patchers.get(bin_rel_path)
        if not patcher:
            binary_path = os.path.join(self._fs_path, bin_rel_path)
            self.log.info("Creating patcher for %s", binary_path)
            patcher = Patcher(binary_path)
            patcher.ensure_backup()
        return patcher

    def run(self, max_runs, timeout_per_run, inspect):
        """Analyzes the init program to extract service information"""

        self.log.info("Starting InitAnalyzer")
        self.log.info("   - Image Path: %s", self._image_path)
        self.log.info("   - Workspace: %s", self._workspace)
        self.log.info("   - Artifact Path: %s", self._artifact_path)

        self._log_phase("Preparing filesystem")
        if not self.prepare_fs():
            return False

        self._log_phase("Scanning init command")
        init_cmd = self.scan_init()
        if not init_cmd:
            return False

        binary_path = init_cmd.split()[0]
        if binary_path.startswith("/"):
            binary_path = binary_path[1:]
        full_binary_path = os.path.join(self._fs_path, binary_path)
        if not os.path.exists(full_binary_path):
            self.log.error("Binary not found: %s", full_binary_path)
            return False

        # Setup basic environment
        self._log_phase("Setting up QEMU running environment")
        setup = RunEnvSetup(self._fs_path, self._artifact_path, self.log)
        if not setup.setup_target(binary_path):
            return False

        # Patch loop
        run_id = 0
        prev_bindings = None
        prev_services = None
        best_run_id = run_id
        best_binding_count = 0
        while True:
            self._log_phase(f"Running Loop [{run_id}/{max_runs}]")

            self._log_phase(f"Running init command [{run_id}]")
            status, trace_path = self.run_and_trace_init(
                init_cmd, run_id=run_id, timeout=timeout_per_run, inspect=inspect
            )

            if status == QemuRunStatus.NORUN:
                self.log.error("QemuRunner failed to run command %s", init_cmd)
                return False

            self._log_phase(f"Parsing trace log [{run_id}]")
            trace = self.parse_trace(trace_path)
            if not trace:
                return False

            with open(
                os.path.join(self._workspace, f"trace_{run_id}.txt"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write(trace.format())

            self._log_phase(f"Infering services [{run_id}]")
            services, bindings = self.infer_services(run_id, trace, None)

            self.log.info("Found %d Bindings", self._count_bindings(bindings))
            self.log.info("Services: %s", services)

            prev_binding_count = self._count_bindings(prev_bindings)
            curr_binding_count = self._count_bindings(bindings)
            if prev_binding_count > curr_binding_count:
                self.log.info(
                    "Less bindings were found, the patching can be broken. Stopping patching loop"
                )
                run_id -= 1  # Use previous run_id
                break
            if curr_binding_count > best_binding_count:
                best_run_id = run_id
                best_binding_count = curr_binding_count
            elif curr_binding_count < best_binding_count:
                self.log.info("Previous patch may be broken, stopping patching loop")
                break
            else:
                self.log.info("No improvement in bindings, continue patching")

            prev_bindings = bindings
            prev_services = services

            self._log_phase(f"Finding exception [{run_id}]")
            exception_pid = self.find_exception(trace)
            if not exception_pid:
                if status != QemuRunStatus.NORMAL:
                    self.log.info("No exception found, will patch the init program")
                    exception_pid = 1 # Force to patch the init program
                else:
                    self.log.info("InitAnalyzer finish because no exception is found")
                    break

            self._log_phase(f"Patching init program [{run_id}]")
            if not self.patch_exception(trace, exception_pid):
                self.log.error("Failed to patch the exception program")
                break

            if run_id + 1 > max_runs:
                self.log.error("Reached maximum number of runs")
                break

            run_id += 1

        self._log_phase(f"Saving final results, using run {best_run_id}")
        self._save_final_results(best_run_id)
        self._clean_workspace()

        return bool(prev_services)

    def prepare_fs(self):
        """Prepare the firmware filesystem for analysis."""
        new_image = False
        image_path = self._image_path
        if not os.path.isfile(image_path):
            self.log.error("Image file does not exist: %s", image_path)
            return False

        image_hash_path = os.path.join(self._workspace, ".image_hash")
        if os.path.exists(image_hash_path):
            existing_image_hash = open(image_hash_path, "r", encoding="utf-8").read()
        else:
            existing_image_hash = ""
        current_image_hash = Files.hash_file(image_path)

        if existing_image_hash != current_image_hash:
            new_image = True
            with open(image_hash_path, "w+", encoding="utf-8") as hash_file:
                hash_file.write(current_image_hash)
        else:
            self.log.info(
                "Image hash matches previous run, reusing extracted filesystem."
            )

        tar_path = os.path.join(self._workspace, "extracted.tar")
        fs_path = self._fs_path

        # Extract image
        extractor = Extractor(verbose=logging.INFO)
        if new_image or not os.path.isfile(tar_path):
            extract_success = extractor.extract(image_path, tar_path)
            if not extract_success:
                self.log.error(
                    "Failed to extract file system from image: %s", image_path
                )
                return False

        # Unpack
        if not extractor.unpack(tar_path, fs_path):
            self.log.error("Failed to unpack extracted file system: %s", tar_path)
            return False

        assert os.path.isdir(fs_path)
        self.log.info("Filesystem is ready at %s", fs_path)
        return True

    def scan_init(self):
        """Find the init program in the filesystem."""
        scanner = InitScanner()
        scanner.run(self._fs_path)
        if not scanner.init_cmds:
            self.log.error("No init program found")
            return None

        self.log.info("Init program found: %s", scanner.init_cmds)
        self.log.info("Use: %s", scanner.init_cmds[0])
        init_cmd = scanner.init_cmds[0]
        self._init_cmd = init_cmd
        self._init_program = init_cmd.split()[0]
        return init_cmd

    def run_and_trace_init(self, init_cmd, run_id, timeout, inspect):
        """Run the init command with Qemu."""
        tmp_dir = os.path.join(self._workspace, "qemu_runner")
        runner = QemuRunner(self._fs_path, init_cmd, tmp_dir=tmp_dir, log=self.log)
        status = runner.run(run_id=run_id, timeout=timeout, inspect=inspect)
        return status, runner.get_log_dir()

    def parse_trace(self, trace_path):
        """Parse the trace log."""
        if not (os.path.isdir(trace_path) and os.listdir(trace_path)):
            self.log.error("No trace log is found")
            return None

        trace = TraceParser.parse(trace_path)
        if not trace:
            self.log.error("Failed to parse trace log")
            return None

        return trace

    def infer_services(self, run_id, trace, r2):
        """Infer services from the parsed trace log."""
        trace_analyzer = TraceAnalyzer(trace)
        services, binding_info = trace_analyzer.run(r2=r2)

        self._save_services(services, run_id)
        self._save_bindings(binding_info, run_id)

        return services, binding_info

    def find_exception(self, trace):
        """Find the exception in the trace."""

        # A process with long run time may indicate a hang
        ps_log_path = os.path.join(self._workspace, "qemu_runner", "ps_aux.log")
        if os.path.exists(ps_log_path):
            with open(ps_log_path, "r", encoding="utf-8") as ps_file:
                ps_list = TraceParser.parse_ps(ps_file)
            for ps in ps_list:
                command = ps.get("COMMAND")
                if not command.startswith("/qemu-"):
                    continue
                try:
                    minutes, seconds = ps.get("TIME").split(":")
                    total_seconds = int(minutes) * 60 + int(seconds)
                except ValueError:
                    continue

                if total_seconds > 60:
                    pid = int(ps.get("PID"))
                    if trace.get_node(pid):
                        node = trace.get_node(pid)
                        cmdline = node.get_cmdline()
                        if cmdline and not cmdline.startswith("<"):
                            return pid

        # We only check the top level processes for tradeoff between performance and accuracy
        max_pid = 500
        for pid in range(1, max_pid):
            node = trace.get_node(pid)
            if not node:
                continue
            cmd = node.get_cmdline()
            if not cmd or cmd.startswith("<"):
                continue

            # Check if the binary is an ELF file
            bin_rel_path = cmd.split()[0].strip()
            bin_name = os.path.basename(bin_rel_path)

            # device related binaries are not interesting
            if bin_name in {"mount", "umount", "insmod", "rmmod", "modprobe", "depmod", "lsmod"}:
                continue

            bin_path = os.path.join(self._fs_path, bin_rel_path[1:])
            if not os.path.exists(bin_path):
                continue
            with open(bin_path, "rb") as f:
                if f.read(4) != b"\x7fELF":
                    continue

            for event in reversed(list(node.syscalls)):
                if "rc" in bin_rel_path and event.name == "exit":
                    if event.args != 0:
                        break
                if event.args_str and b"SIGSEGV" in event.args_str:
                    break
            else:
                continue

            return node.pid
        return None

    def patch_exception(self, trace, exception_pid):
        """Patch the init program."""

        if not self._patch_history:
            self._patch_history = PatchHistory()
        patch_history = self._patch_history

        exception_node = trace.get_node(exception_pid)
        assert exception_node

        exception_cmd = exception_node.get_cmdline().split()[0].strip()
        self.log.info("Exception found in process %d: %s", exception_pid, exception_cmd)

        self.log.info("Patching binary")
        exception_bin = exception_cmd.split()[0]
        patcher = self.get_patcher(exception_bin)
        trace_events = trace.get_node(exception_pid).get_events()
        patch_success = patcher.patch_by_events(
            trace_events, patch_history, max_depth=1
        )
        if not patch_success:
            self.log.error("Failed to patch binary")

        self.log.info("Patching History:")
        for patch in patch_history.patches:
            self.log.info("    - %s", str(patch))

        return patch_success

    def _clean_workspace(self):
        """Clean up the workspace."""
        self.log.info("Cleaning up workspace")

        for filename in os.listdir(self._workspace):
            if re.match(r"trace_\d+\.txt", filename):
                os.remove(os.path.join(self._workspace, filename))
            elif re.match(r"bindings_\d+\.json", filename):
                os.remove(os.path.join(self._workspace, filename))
            elif re.match(r"services_\d+\.json", filename):
                os.remove(os.path.join(self._workspace, filename))

        qr_workspace = os.path.join(self._workspace, "qemu_runner")
        for filename in os.listdir(qr_workspace):
            if filename.endswith(".log"):
                os.remove(os.path.join(qr_workspace, filename))
            elif filename == "ghqemu":
                shutil.rmtree(os.path.join(qr_workspace, filename))
            elif re.match(r"logs\.\d+\.tar", filename):
                os.remove(os.path.join(qr_workspace, filename))
            elif re.match(r'fs\.\d+\.tar', filename):
                os.remove(os.path.join(qr_workspace, filename))
            elif re.match(r"ramfs.*\.tar", filename):
                os.remove(os.path.join(qr_workspace, filename))

    def _save_final_results(self, run_id):
        """Save the final results."""
        fs_tar_path = os.path.join(self._workspace, "qemu_runner", f"fs.{run_id}.tar")
        if os.path.isfile(fs_tar_path):
            shutil.copy(fs_tar_path, os.path.join(self._workspace, "fs.tar"))

        src_log_path = os.path.join(
            self._workspace, "qemu_runner", f"logs.{run_id}.tar"
        )
        log_path = os.path.join(self._workspace, "logs.tar")
        shutil.copy(src_log_path, log_path)

        tar = tarfile.open(log_path, mode="a")
        trace_path = os.path.join(self._workspace, f"trace_{run_id}.txt")
        if os.path.isfile(trace_path):
            tar.add(trace_path, arcname="trace.txt")

        bindings_path = os.path.join(self._workspace, f"bindings_{run_id}.json")
        if os.path.isfile(bindings_path):
            tar.add(bindings_path, arcname="bindings.json")

        services_path = os.path.join(self._workspace, f"services_{run_id}.json")
        if os.path.isfile(services_path):
            tar.add(services_path, arcname="services.json")

        analysis_log_path = os.path.join(self._workspace, "analyzer_output.log")
        if os.path.isfile(analysis_log_path):
            tar.add(analysis_log_path, arcname="analyzer_output.log")

        # Also save init run logs
        if run_id != 0:
            trace_path = os.path.join(self._workspace, "trace_0.txt")
            if os.path.isfile(trace_path):
                tar.add(trace_path, arcname="trace_0.txt")

            bindings_path = os.path.join(self._workspace, "bindings_0.json")
            if os.path.isfile(bindings_path):
                tar.add(bindings_path, arcname="bindings_0.json")

            services_path = os.path.join(self._workspace, "services_0.json")
            if os.path.isfile(services_path):
                tar.add(services_path, arcname="services_0.json")

        tar.close()

    def _save_bindings(self, bindings, run_id):
        """Save bindings to a file."""
        if not bindings:
            return
        binding_path = os.path.join(self._workspace, f"bindings_{run_id}.json")
        with open(
            binding_path,
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(bindings, f)

    def _save_services(self, services, run_id):
        """Save services to a file."""
        if not services:
            return
        service_path = os.path.join(self._workspace, f"services_{run_id}.json")
        with open(
            service_path,
            "w",
            encoding="utf-8",
        ) as f:
            json.dump([service.to_dict() for service in services], f)

    def _count_bindings(self, bindings):
        """Count the number of bindings."""
        if not bindings:
            return 0
        return len(bindings.get("remote", [])) + len(bindings.get("local", []))

    def _log_phase(self, phase):
        self.log.info("============== %s ==============", phase)
