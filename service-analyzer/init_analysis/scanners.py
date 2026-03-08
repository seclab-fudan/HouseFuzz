#!python3
# pylint: disable=invalid-name
"""
Scanners of firmware filesystem.
"""
from __future__ import annotations
import os
import tarfile
from enum import Enum

from .items import FSItem, TarItem


class InitScanner:
    """Class to examine the init system of a tar firmware filesystem."""

    INIT_FILE_NAMES = [
        "inittab",
        "preinit",
        "rcS",
        "rc",
        "sysinit",
        "rc.sh",
        "init.sh",
        "linuxrc",
    ]

    def __init__(self):
        self.init_cmds = []

    def reset(self):
        """Reset results."""
        self.init_cmds = []

    def run(self, target_path):
        """Examine the init system of a tar firmware filesystem.
        :param target_path: The path to the tar firmware filesystem or firmware filesystem folder.
        :return: True if the tar file exists and is valid.
        """
        self.reset()
        if os.path.isfile(target_path):
            return self._run_on_tar(target_path)
        else:
            return self._run_on_dir(target_path)

    def _run_on_dir(self, target_path):
        # Find the first tar file in the directory
        file_items = []
        for root, _, files in os.walk(target_path):
            root_rel = os.path.relpath(root, target_path)
            for file in files:
                file_rel = os.path.join(root_rel, file)
                file_item = FSItem(target_path, file_rel)
                file_items.append(file_item)

        return self._run_on_items(file_items)

    def _run_on_tar(self, target_path):
        tar = tarfile.open(target_path)

        tar_items = [
            TarItem(tar, tar_info)
            for tar_info in tar
            if (tar_info.isfile() or tar_info.is_lnk())
        ]

        return self._run_on_items(tar_items)

    def _run_on_items(self, items):

        # Directly looking for init binary
        cmds = []
        for item in items:
            if os.path.basename(item.path) == "init" and item.size > 0x20:
                cmds.append(item.path)
        self.init_cmds = cmds

        # Looking for inittab, which is typically used by System V init system
        for item in items:
            # If /etc/inittab exists, it is likely to be System V
            # Busybox init, may dynamically generate inittab
            if os.path.basename(item.path) == "inittab":
                cmds = self._examine_inittab(item)
                if not cmds:
                    continue
                self.init_cmds.extend(cmds)

        return bool(self.init_cmds)

    def _examine_inittab(self, item: TarItem):
        # Basic parsing of inittab
        content = item.open().read().decode("utf-8")
        action_cmds = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            fields = line.split(":", 3)
            if len(fields) != 4:
                continue

            _identifier, _runlevels, action, command = fields
            # Based on action, infer boot-time commands
            # actions: See https://manpages.debian.org/jessie/sysvinit-core/inittab.5.en.html

            # We ignore non-boot-time commands for now
            if action not in [
                "respawn",
                "respawnlate",
                "restart",  # This is not a boot-time command, but we include it for now
                "wait",
                "boot",
                "bootwait",
                "once",
                "sysinit",
                "initdefault",
            ]:
                continue

            # In inittab, a command line starting with '-' means that the command should be run with a login shell.
            # We just ignore it for now.
            if not command or command.startswith("-"):
                continue

            command_path = command.split()[0]
            command_item = item.get_abs_item(command_path)
            if not command_item:
                # The command is not found in the tar file
                print(f"Command not found: {command_path}")
                continue

            action_cmds.setdefault(action, set()).add("/bin/sh " + command)

        cmds = []
        for action, commands in action_cmds.items():
            cmds.extend(commands)

        return cmds
