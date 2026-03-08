import os
import logging
import time
import shutil
import traceback
from enum import Enum
import tarfile
import subprocess
from subprocess import run, PIPE
import pathlib
import re
import tempfile

import docker
from docker.errors import BuildError, APIError, ImageNotFound
import docker.models
import docker.models.containers
from requests.exceptions import RequestException

from .utils import Files


RAND = (
    "8467206204610564372101238468369273619216273019100147216372162374" * 100
)  # "random number" string for 'entropy'


class QemuRunStatus(Enum):
    """Qemu run status enum"""

    NORMAL = 0
    NORUN = 1
    EXCEPTION = 2


class QemuRunner:
    """Run command in docker container with qemu and analyze logs."""

    BASE_IMAGE_NAME = "qemu_runner_base"
    DOCKER_HOST = os.getenv("DOCKER_HOST", "unix:///var/run/docker.sock")

    ERROR_CODES = [
        139,  # segfault
        255,  # can also mean exiting with -1
        20,  # 'network' error (peripheral device)
        -11,
        127,  # assertion failed (invalid command)
        132,  # illegal instruction
        134,  # abort
        -6,
        135,  # bus error
        136,  # arithmetic error
        -8,
    ]
    TIMEOUT_CODE = 124  # linux timeout return value
    VERBOSE_LOG_TIMEOUT_MULTIPLIER = 5

    def __init__(self, fs_path, cmdline, tmp_dir, log=None):
        self._fs_path = fs_path
        self._cmdline = cmdline
        self._tmpdir = tmp_dir

        os.makedirs(self._tmpdir, exist_ok=True)

        os.environ["DOCKER_HOST"] = self.DOCKER_HOST
        self._client = docker.from_env()
        self._image = None
        self._container = None

        self.log = log or logging.getLogger(__name__)

    def run(self, run_id, timeout, inspect):
        """Run cmdline and analyzing logs."""
        status = QemuRunStatus.NORUN
        try:
            self._cleanlogs()
            self._make_docker_compose()
            if not self._prepare_base_image():
                return
            image = self._build_docker_image()
            if not image:
                return

            exec_command = f"/fs/run_command.sh {self._cmdline}"
            container, status = self._run_docker_image(image, exec_command, timeout, inspect)
            if not container:
                return

            self._collect_logs(container, run_id)
            # run(f"docker exec -it {container.name} /bin/bash", shell=True, check=False)
            self._collect_fs(container, run_id)
        except Exception as e:  # pylint: disable=broad-except
            self.log.error("Error: %s", str(e))
            self.log.error("Traceback: %s", traceback.format_exc())
        finally:
            self._cleanup()

        return status

    def get_log_dir(self):
        """Get the path to the qemu log directory."""
        return os.path.join(self._tmpdir, "ghqemu")

    def get_output_path(self):
        """Get the path to the docker output log."""
        return os.path.join(self._tmpdir, "docker_output.log")

    def _cleanup(self):
        self.log.info("Cleaning up")
        retry_times = 3
        retry_wait = 5
        if self._container:
            self.log.info("Stopping container %s", self._container.name)
            for _ in range(retry_times):
                try:
                    self._container.stop()
                    break
                except APIError:
                    self.log.error("Failed to stop container: %s. Retrying", self._container.name)
                    time.sleep(retry_wait)
            self.log.info("Removing container %s", self._container.name)
            for _ in range(retry_times):
                try:
                    self._container.remove()
                    break
                except APIError:
                    self.log.error("Failed to remove container: %s. Retrying", self._container.name)
                    time.sleep(retry_wait)
        if self._image:
            self.log.info("Removing image %s", self._image.id)
            for _ in range(retry_times):
                try:
                    self._client.images.remove(self._image.id)
                    break
                except APIError:
                    self.log.error("Failed to remove image %s. Retrying", self._image.id)
                    time.sleep(retry_wait)

    def _cleanlogs(self):
        logs_dir = os.path.join(self._tmpdir, "ghqemu")
        if os.path.exists(logs_dir):
            shutil.rmtree(logs_dir)
        docker_output = os.path.join(self._tmpdir, "docker_output.log")
        if os.path.exists(docker_output):
            os.remove(docker_output)

    def _prepare_base_image(self):
        try:
            self._client.images.get(self.BASE_IMAGE_NAME)
            return True
        except ImageNotFound:
            pass

        base_dockerfile_content = """FROM ubuntu:20.04
        ENV DEBIAN_FRONTEND=noninteractive
        RUN apt-get update && apt-get install -y net-tools
        """
        self.log.info("Building base image %s", self.BASE_IMAGE_NAME)
        try:
            file_fp = tempfile.TemporaryFile("wb+")
            file_fp.write(base_dockerfile_content.encode("utf-8"))
            file_fp.seek(0)
            self._client.images.build(
                fileobj=file_fp,
                tag=self.BASE_IMAGE_NAME,
            )
            return True
        except BuildError as e:
            self.log.error("Failed to build base image: %s", str(e.msg))
        except APIError as e:
            self.log.error("Failed to build base image: %s", str(e))
        except RequestException as e:
            self.log.error("Failed to build base image: %s", str(e))
        return False

    def _build_docker_image(self):
        tmpdir = self._tmpdir
        os.makedirs(tmpdir, exist_ok=True)

        tmp_fs_path = os.path.join(tmpdir, "fs")
        Files.copy_directory(self._fs_path, tmp_fs_path)

        dockerfile_path = os.path.join(tmpdir, "Dockerfile")
        dockerfile_content = (
            f"FROM {self.BASE_IMAGE_NAME}"
            + """
            COPY fs /fs
            RUN mkdir -p /fs/ghdev /fs/ghproc /fs/ghtmp /fs/ghqemu /fs/dev /fs/proc /fs/sys
            RUN /fs/setup_dev.sh /fs/greenhouse/busybox /fs/ghdev
            CMD ["/bin/bash"]"""
        )
        with open(dockerfile_path, "w", encoding="utf-8") as docker_file:
            docker_file.write(dockerfile_content)

        self.log.info("Building docker image")
        build_success = False
        max_retry = 2
        cur_retry = 0
        retry_wait = 20
        while not build_success:
            try:
                image, _json_log = self._client.images.build(path=tmpdir, rm=True)
            except docker.errors.APIError as e:
                self.log.error("    - API error: %s. backing off and retrying %d/%d in %ds", str(e), cur_retry, max_retry, retry_wait)
                cur_retry += 1
                if cur_retry >= max_retry:
                    self.log.error("Failed to build image")
                    return None
                time.sleep(retry_wait)
                continue
            except BuildError as e:
                self.log.error(
                    "    - Build error: %s. backing off and retrying %d/%d in %ds",
                    str(e.msg),
                    cur_retry,
                    max_retry,
                    retry_wait
                )
                self.log.error(
                    "Build logs: %s", "\n".join([str(log) for log in e.build_log])
                )
                cur_retry += 1
                if cur_retry >= max_retry:
                    self.log.error("Failed to build image")
                    return None
                time.sleep(retry_wait)
                continue
            build_success = True
            self._image = image

        self._client.networks.prune()  # cleanup
        return image

    def _run_docker_image(self, image, exec_command, timeout, inspect=False):
        status = QemuRunStatus.NORUN
        self.log.info("Creating and running new temp container...")
        self.log.info("Running command: %s", exec_command)

        try:
            container: docker.models.containers.Container = self._client.containers.run(
                image,
                exec_command,
                detach=True,
                mem_limit="64G",
                ipc_mode="shareable",
                privileged=True,
                ulimits=[
                    # Limit core dumps
                    docker.types.Ulimit(
                        name="core",
                        soft=10,
                        hard=10,
                    )
                ],
            )
            self._container = container
        except APIError as e:
            self.log.error("Failed to start container: %s", str(e))
            return None, QemuRunStatus.NORUN

        try:
            if inspect:
                self.log.info("Inspecting container")
                run(f"docker exec -it {self._container.name} /bin/bash", shell=True, check=False)
            _response = container.wait(timeout=timeout)
            status = QemuRunStatus.EXCEPTION
        except APIError as e:
            self.log.error("Failed to wait for container: %s", str(e))
            status = QemuRunStatus.NORUN
        except RequestException:
            self.log.error("Timeout reached for container")
            status = QemuRunStatus.NORMAL

        docker_output = os.path.join(self._tmpdir, "docker_output.log")
        data = container.logs()
        with open(docker_output, "wb") as log_file:
            log_file.write(data)
        # check for core dump
        if b"core dumped" in data:
            status = QemuRunStatus.EXCEPTION

        log_file.close()

        return container, status

    def _kill_container(self, container):
        self.log.info("Killing container %s", container.name)
        try:
            container.kill()
        except APIError:
            self.log.error("Failed to kill container: %s", container.name)

    def _collect_logs(self, container, run_id):
        self.log.info("Collecting logs")

        stream, _ = container.get_archive(os.path.join("/fs/ghqemu"))
        tmp_log_tar_path = os.path.join(self._tmpdir, f"logs.{run_id}.tar")
        with open(tmp_log_tar_path, "wb") as log_tarf:
            for chunk in stream:
                log_tarf.write(chunk)

        logs_dir = os.path.join(self._tmpdir, "ghqemu")
        shutil.rmtree(logs_dir, ignore_errors=True)
        shutil.unpack_archive(tmp_log_tar_path, extract_dir=self._tmpdir)

        tar = tarfile.open(tmp_log_tar_path, mode="a")

        # Collect ps aux
        try:
            _, stream = self._container.exec_run(
                ["ps", "aux"], stdout=True, stderr=True, stream=True
            )
            ps_output = os.path.join(self._tmpdir, "ps_aux.log")
            with open(ps_output, "wb") as ps_aux_log:
                for chunk in stream:
                    ps_aux_log.write(chunk)
            tar.add(ps_output, arcname="ps_aux.log")
        except:  # pylint: disable=bare-except
            pass

        # Collect netstat anp
        try:
            _, stream = self._container.exec_run(
                ["netstat", "-anp"], stdout=True, stderr=True, stream=True
            )
            netstat_output = os.path.join(self._tmpdir, "netstat_anp.log")
            with open(netstat_output, "wb") as netstat_log:
                for chunk in stream:
                    netstat_log.write(chunk)
            tar.add(netstat_output, arcname="netstat_anp.log")
        except:  # pylint: disable=bare-except
            pass

        docker_output = os.path.join(self._tmpdir, "docker_output.log")
        if os.path.exists(docker_output):
            tar.add(docker_output, arcname="docker_output.log")

        tar.close()
        # os.remove(tmp_log_tar_path)

    def _collect_fs(self, container, run_id):
        self.log.info("Cleaning fs")
        collect_ramfs = True
        try:
            self._container.exec_run(
                ["rm", "-rf", "/fs/ghqemu", "/fs/SIGSEGV_HAPPENED", "/fs/*.core", "/fs/core.*"]
            )
        except docker.errors.APIError:
            self.log.error("Failed to clean fs")
            collect_ramfs = False

        # get ramfs
        ramfs_tar_path = os.path.join(self._tmpdir, f"ramfs.{run_id}.tar")
        if collect_ramfs:
            self.log.info("Collecting ramfs")
            tmp_ramfs_tar_path = os.path.join(self._tmpdir, "ramfs.tar")
            wrap_ramfs_tar_path = os.path.join(self._tmpdir, "ramfs.tar.tar")
            _, stream = self._container.exec_run(
                ["mount"], stdout=True, stderr=True, stream=True
            )
            buffer = b""
            for chunk in stream:
                buffer += chunk
            for line in buffer.split(b"\n"):
                if b"on /fs" in line and b"ramfs" in line:
                    ramfs_path = line.split(b" ")[2].decode("utf-8")
                    self.log.info("Found ramfs path: %s", ramfs_path)
                    # get ramfs tar and merge with fs tar
                    ramfs_path = ramfs_path.replace("/fs", "")
                    self._container.exec_run(["tar", "-cf", "/ramfs.tar", ramfs_path])
                    stream, _ = self._container.get_archive("/ramfs.tar")
                    with open(wrap_ramfs_tar_path, "wb") as ramfs_tar:
                        for chunk in stream:
                            ramfs_tar.write(chunk)
                    with tarfile.open(wrap_ramfs_tar_path, mode="r") as tar:
                        tar.extractall(self._tmpdir)
                    if os.path.exists(ramfs_tar_path):
                        # merge ramfs tar with existing ramfs tar
                        self._merge_tar(ramfs_tar_path, tmp_ramfs_tar_path)
                    else:
                        shutil.move(tmp_ramfs_tar_path, ramfs_tar_path)

        # Kill process before collecting fs to trigger cleanup
        # ps aux | egrep qemu | egrep -v /init | awk '{print $2}' | xargs -t kill
        self._kill_container(container)

        self.log.info("Collecting filesystem")
        tar_name = f"fs.{run_id}.tar"
        fs_tar_path = os.path.join(self._tmpdir, tar_name)
        stream, _ = container.get_archive("/fs")
        with open(fs_tar_path, "wb") as fs_tar:
            for chunk in stream:
                fs_tar.write(chunk)
        # add ramfs tar content to fs tar
        if os.path.exists(ramfs_tar_path):
            self._merge_tar(fs_tar_path, ramfs_tar_path)

        # for clean_file in ["fs/ghqemu", "fs/SIGSEGV_HAPPENED"]:
        #     subprocess.run(
        #         ["tar", "-f", fs_tar_path, "--delete", clean_file],
        #         stdout=PIPE,
        #         stderr=PIPE,
        #         check=False,
        #     )

        return fs_tar_path

    def _merge_tar(self, dst_tar_path, src_tar_path):
        # cat  receiverTar1.tar receivedTar2.tar ... >>alltars.tar
        # tar -itvf alltars.tar
        run(["tar", "--concatenate", "--file", dst_tar_path, src_tar_path], check=False)

    def _make_docker_compose(self, mac=""):
        dest = self._tmpdir
        docker_compose_path = os.path.join(dest, "docker-compose.yml")
        print("Writing docker-compose file to ", docker_compose_path)
        lines = [
            'version: "2.2"\n',
            "services:",
            "  gh_rehosted:",
            "    build: .",
            "    privileged: true",
            "    environment:",
            "      - START_PID=0",
            "    command: /fs/run_command.sh " + f"{self._cmdline}",
        ]
        with open(docker_compose_path, "w+", encoding="utf-8") as dc_file:
            dc_file.write("\n".join(lines))
            if mac:
                dc_file.write(f'    mac_address: "{mac}"\n')


class RunEnvSetup:
    """Setup the environment to run the target binary."""

    def __init__(self, fs_path, artifact_path, log=None) -> None:
        self._fs_path = fs_path
        self._artifact_path = artifact_path

        self.log = log or logging.getLogger(__name__)
        self._nvram_map = dict()

    def setup_target(self, binary_path):
        """Setup the environment to run the target binary."""
        # chmod +rw entire directory so its editable
        subprocess.run(["chmod", "-R", "a+rw", self._fs_path], check=False)

        full_path = os.path.join(self._fs_path, binary_path)
        full_path = str(pathlib.Path(full_path).resolve())  # handle symlinks
        subprocess.run(["chmod", "-R", "a+x", full_path], check=False)

        self.log.info("Checking binary at %s", full_path)
        sp = subprocess.run(["file", full_path], stdout=PIPE, stderr=PIPE, check=False)
        if sp.returncode != 0:
            self.log.error("Failed to run file command")
            return False
        arch = PlanterUtils.get_arch_from_file_output(sp.stdout)
        clibc = PlanterUtils.get_clib_from_file_output(sp.stdout)

        if not arch:
            self.log.error("Failed to determine architecture")
            return False

        if not self._setup_bins(arch):
            self.log.error("Failed to setup bins")
            return False
        self._setup_devfiles()
        self._remove_reboots()
        self._setup_custom_libraries(arch, clibc)
        return True

    def _setup_bins(self, arch):
        # copy relevant qemu static
        fs_path = self._fs_path
        qemu_name = PlanterUtils.get_qemu_by_arch(arch)
        if not qemu_name:
            self.log.error(f"Failed to determine qemu name for arch {arch}")
            return False
        qemu_path = os.path.join(self._artifact_path, "external_qemu", qemu_name)
        qemu_dst_path = os.path.join(fs_path, qemu_name)

        Files.copy_file(qemu_path, qemu_dst_path)

        # copy statically compiled helper binaries
        gh_path = os.path.join(fs_path, "greenhouse")
        ip_path = os.path.join(self._artifact_path, "ip")
        busybox_path = os.path.join(self._artifact_path, "busybox")
        ip_dst_path = os.path.join(fs_path, "greenhouse", "ip")
        busybox_dst_path = os.path.join(fs_path, "greenhouse", "busybox")
        Files.mkdir(gh_path)
        Files.copy_file(ip_path, ip_dst_path)
        Files.copy_file(busybox_path, busybox_dst_path)

        # copy scripts
        runner_path = os.path.join(self._artifact_path, "ghscripts", "run_command.sh")
        runner_dest = os.path.join(self._fs_path, "run_command.sh")
        qemu_wrapper_path = os.path.join(
            self._artifact_path, "ghscripts", "qemu-wrapper"
        )
        qemu_wrapper_dest = os.path.join(self._fs_path, "qemu-wrapper")
        Files.copy_file(runner_path, runner_dest)
        Files.copy_file(qemu_wrapper_path, qemu_wrapper_dest)

        with open(qemu_wrapper_dest, "rb+") as fp:
            content = fp.read()
            content = re.sub(rb"qemu-\w+-static", qemu_name.encode("utf-8"), content)
            fp.seek(0)
            fp.write(content)
        return True

    def _setup_custom_libraries(self, arch, clibc):
        fs_path = self._fs_path

        lib_path = os.path.join(fs_path, "lib")
        nvram_faker_path = os.path.join(self._artifact_path, "libnvram_faker")
        target_nvram_faker_path = os.path.join(
            nvram_faker_path, "lib", arch, clibc, "libnvram-faker.so"
        )
        fake_libnvram_path = os.path.join(lib_path, "libnvram-faker.so")
        Files.copy_file(target_nvram_faker_path, fake_libnvram_path)

        # backup and replace the original libnvram in case hook does not work
        real_libnvram_path = os.path.join(lib_path, "libnvram.so")
        if os.path.exists(real_libnvram_path):
            os.rename(real_libnvram_path, real_libnvram_path + ".bak")
        Files.copy_file(target_nvram_faker_path, real_libnvram_path)

        # scan default nvram.ini in fs_path
        all_files = [file_path for file_path in Files.get_all_files(self._fs_path)]
        nvram_files = [
            file_path
            for file_path in all_files
            if "nvram" in file_path
            and os.path.isfile(file_path)
            and open(file_path, "rb").read(4) != b"\x7fELF"
        ]
        self.log.info("    - loading default nvram from: %s", nvram_files)
        default_nvram_map = {}
        for nvram_file in nvram_files:
            default_nvram_map.update(self._load_default_nvram(nvram_file))

        # make nvram ini
        nvram_init_path = os.path.join(fs_path, "nvram.ini")
        nvram_key_value_path = os.path.join(fs_path, "gh_nvram")
        Files.touch_file(nvram_init_path, root=fs_path)
        if not os.path.exists(nvram_key_value_path):
            Files.mkdir(nvram_key_value_path, root=fs_path)
            os.chmod(nvram_key_value_path, 0o777)

        nvram_ref_path = os.path.join(nvram_faker_path, "conf", "nvram.ini")
        nvram_ref_map = self._load_default_nvram(nvram_ref_path)

        brand = os.path.dirname(os.path.dirname(os.path.dirname(self._fs_path)))
        nvram_brand_path = os.path.join(nvram_faker_path, "conf", brand, "nvram.ini")
        nvram_brand_map = self._load_default_nvram(nvram_brand_path)

        self._nvram_map.update(nvram_ref_map)
        self._nvram_map.update(nvram_brand_map)
        self._nvram_map.update(default_nvram_map)
        self._write_nvram(self._nvram_map)

        return True

    def _load_default_nvram(self, path):
        if not path or not os.path.exists(path):
            return {}
        
        def load_by_sep(path, sep):
            nvram_map = dict()
            with open(path, "r", encoding="utf-8") as nvram_fp:
                content = nvram_fp.read()
                for line in content.split(sep):
                    line = line.strip()
                    if line and "=" in line:
                        array = line.split("=")
                        key = array[0].strip()
                        value = array[1].strip()
                        if key and key.isprintable():
                            nvram_map[key] = value
            return nvram_map

        nvram_map = load_by_sep(path, "\n")
        if len(nvram_map) < 3:
            new_nvram_map = load_by_sep(path, ":")
            if len(new_nvram_map) > len(nvram_map):
                nvram_map = new_nvram_map
        return nvram_map

    def _write_nvram(self, nvram_map):
        for key, value in nvram_map.items():
            key = key.strip().strip("/")
            if not key:
                continue
            if "/" in key:
                key = key.replace("/", "_")
            key_path = os.path.join(self._fs_path, "gh_nvram", key)
            if os.path.isdir(key_path):
                continue
            if not os.path.exists(os.path.dirname(key_path)):
                os.makedirs(os.path.dirname(key_path))
            with open(key_path, "w", encoding="utf-8") as key_file:
                key_file.write(value)
            os.chmod(key_path, 0o666)

    def _setup_devfiles(self):
        # setup dev files
        fs_path = self._fs_path

        self.log.info("    - setup /dev and /ghdev files")
        Files.rm_target(os.path.join(fs_path, "dev", "null"))
        Files.rm_target(os.path.join(fs_path, "dev", "urandom"))
        Files.rm_target(os.path.join(fs_path, "dev", "random"))
        Files.touch_file(
            os.path.join(fs_path, "dev", "null"), root=fs_path, silent=True
        )  # empty file
        Files.write_file(
            os.path.join(fs_path, "dev", "urandom"), RAND, root=fs_path, silent=True
        )  # 'random' bytes for entropy
        Files.write_file(
            os.path.join(fs_path, "dev", "random"), RAND, root=fs_path, silent=True
        )  # 'random' bytes for entropy
        print(os.path.join(fs_path, "dev"))
        print(os.path.join(fs_path, "ghdev"))
        if os.path.exists(os.path.join(fs_path, "dev")):
            Files.copy_directory(
                os.path.join(fs_path, "dev"), os.path.join(fs_path, "ghdev")
            )
        if os.path.exists(os.path.join(fs_path, "proc")):
            Files.copy_directory(
                os.path.join(fs_path, "proc"), os.path.join(fs_path, "ghproc")
            )
        Files.mkdir(os.path.join(fs_path, "ghtmp"))

        setup_dev_path = os.path.join(self._artifact_path, "setup_dev.sh")
        setup_dev_dest = os.path.join(fs_path, "setup_dev.sh")
        Files.copy_file(setup_dev_path, setup_dev_dest)

    def _remove_reboots(self):
        # setup dev files
        fs_path = self._fs_path
        print("    - removing reboot and shutdown scripts")
        reboot_files = PlanterUtils.find_files(
            "reboot", fs_path, resolve_symlinks=False
        )
        shutdown_files = PlanterUtils.find_files(
            "shutdown", fs_path, resolve_symlinks=False
        )
        dummy_script_path = os.path.join(self._artifact_path, "dummy.sh")

        for rf in reboot_files:
            Files.rm_target(rf)
            Files.copy_file(dummy_script_path, rf)

        for sf in shutdown_files:
            Files.rm_target(sf)
            Files.copy_file(dummy_script_path, sf)


class PlanterUtils:
    """Utilities for Planter"""

    @classmethod
    def get_arch_from_file_output(cls, outline):
        """Get the architecture of the binary from the output of the file command"""
        if b"64-bit" in outline:
            if b" ARM" in outline and b" LSB" in outline:
                return "arm64"
            elif b" x86-64" in outline:
                return "x86_64"
            elif b" MIPS" in outline and b" MSB" in outline:
                return "mips64"
            elif b" MIPS" in outline and b" LSB" in outline:
                return "mips64el"
        else:
            if b" ARM" in outline and b" MSB" in outline:
                return "armeb"
            elif b" ARM" in outline and b" LSB" in outline:
                return "arm"
            elif b" x86-64" in outline:
                return "x86_64"
            elif b" 80386" in outline:
                return "x86"
            elif b" MIPS" in outline and b" MSB" in outline:
                return "mips"
            elif b" MIPS" in outline and b" LSB" in outline:
                return "mipsel"
        return None

    @classmethod
    def get_clib_from_file_output(cls, outline):
        """Get the C library used by the binary from the output of the file command"""
        if b"uClibc" in outline:
            return "uclibc"
        elif b"GNU/Linux" in outline:
            return "glibc"
        elif b"musl" in outline:
            return "musl"
        return "glibc"  # default

    @classmethod
    def get_qemu_by_arch(cls, arch):
        """Get the QEMU architecture for the given architecture"""
        arch_map = {
            "arm": "qemu-arm-static",
            "armeb": "qemu-armeb-static",
            "armeb32": "qemu-armeb-static",
            "arm64": "qemu-aarch64-static",
            "armeb64": "qemu-aarch64_be-static",
            "x86": "qemu-i386-static",
            "x86_64": "qemu-x86_64-static",
            "mips": "qemu-mips-static",
            "mipsel": "qemu-mipsel-static",
            "mips64": "qemu-mips64-static",
            "mips64el": "qemu-mips64el-static",
        }
        return arch_map.get(arch, None)

    @classmethod
    def find_files(
        cls, filename, fs_path, include_backups=False, resolve_symlinks=True, skip=None
    ):
        """Find files with the given filename in the filesystem path."""
        backup_tags = ["bak", "bak2", "bkup"]
        found = []
        if not skip:
            skip = []
        for root, _, files in os.walk(fs_path):
            for f in files:
                if f == filename:
                    file_path = os.path.join(root, f)
                    if os.path.dirname(file_path) == fs_path:
                        continue  # skip files in 'root' dir
                    if os.path.islink(file_path):
                        if resolve_symlinks:
                            file_path = str(
                                pathlib.Path(file_path).resolve()
                            )  # handle symlinks
                        if not file_path.startswith(
                            fs_path
                        ):  # handle symlinks that resolve to outside root folder
                            while file_path.startswith("/") or file_path.endswith("/"):
                                file_path = file_path.strip("/")
                            file_path = os.path.join(fs_path, file_path)
                    if file_path in skip or file_path in found:
                        continue
                    if not os.path.exists(file_path):
                        continue
                    found.append(file_path)
                if include_backups:
                    for tag in backup_tags:
                        if f.lower().endswith(filename.lower() + "." + tag):
                            file_path = os.path.join(root, f)
                            if os.path.dirname(file_path) == fs_path:
                                continue  # skip files in 'root' dir
                            if os.path.islink(file_path):
                                if resolve_symlinks:
                                    file_path = str(
                                        pathlib.Path(file_path).resolve()
                                    )  # handle symlinks
                                if not file_path.startswith(
                                    fs_path
                                ):  # handle symlinks that resolve to outside root folder
                                    while file_path.startswith(
                                        "/"
                                    ) or file_path.endswith("/"):
                                        file_path = file_path.strip("/")
                                    file_path = os.path.join(fs_path, file_path)
                            if file_path in skip or file_path in found:
                                continue
                            if not os.path.exists(file_path):
                                continue
                            found.append(file_path)
        return found