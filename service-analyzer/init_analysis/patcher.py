"""
Patcher for binary file
"""

import os
import shutil
from dataclasses import dataclass

import r2pipe

from .trace_parser import TranslateBlock


class PatchHistory:
    """Patch history"""

    def __init__(self):
        self.patches = []

    def add_patch(self, patch):
        """Add patch"""
        self.patches.append(patch)

    def apply_patches(self, r2):
        """Apply all patches"""
        for patch in self.patches:
            patch.apply(r2)


@dataclass
class Patch:
    """Patch information"""

    bin_path: str
    reason_str: int
    reason_addr: int
    patch_cmd: str
    patch_info: dict

    def apply(self, r2):
        """Apply patch"""
        if r2:
            r2.cmd(self.patch_cmd)
        else:
            os.system(self.patch_cmd)


class Patcher:
    """Patcher for binary file"""

    def __init__(self, bin_path, show_warning=False):
        self.bin_path = bin_path
        flags = ["-w"]
        if not show_warning:
            flags.append("-2")
        self.r2 = r2pipe.open(bin_path, flags=flags)
        self.r2.cmd("aaa")
        self.r2.cmd("e log.quiet=true")

    def ensure_backup(self):
        """Create backup of the binary file"""
        bak_path = self.bin_path + ".bak"
        if not os.path.exists(bak_path):
            shutil.copy(self.bin_path, self.bin_path + ".bak")

    def restore_backup(self):
        """Restore from backup"""
        bak_path = self.bin_path + ".bak"
        if os.path.exists(bak_path):
            shutil.copy(self.bin_path + ".bak", self.bin_path)
            return True
        return False

    def patch_by_events(self, trace_events, history: PatchHistory, max_depth = 1):
        """Patch binary file by event trace log"""
        trace_addrs = [
            event.pc for event in trace_events if isinstance(event, TranslateBlock)
        ]
        program_addrs = [
            addr for addr in trace_addrs if addr >= 0x3F000000
        ]

        if len(program_addrs) < 10:
            return self.patch_with_empty(self.bin_path, history)

        infer_res = self._infer_func_call_patch_site(trace_addrs, max_depth=max_depth)
        if not infer_res:
            return False

        call_addr, reason_addr, depth, skipped_func_size = infer_res

        patch = Patch(
            bin_path=self.bin_path,
            reason_str="terminate",
            reason_addr=reason_addr,
            patch_cmd=f"wa nop @ {call_addr:#x}",
            patch_info={
                "patch_addr": call_addr,
                "max_depth": max_depth,
                "depth": depth,
                "skipped_func_size": skipped_func_size,
            },
        )
        patch.apply(self.r2)
        history.add_patch(patch)
        return True

    def patch_with_empty(self, bin_path, history: PatchHistory):
        """Patch binary file by removing it"""
        patch = Patch(
            bin_path="",
            reason_str="terminate",
            reason_addr=0,
            patch_cmd=f"mv {bin_path} {bin_path}.bak",
            patch_info={},
        )
        patch.apply(None)
        history.add_patch(patch)
        return True

    def _infer_func_call_patch_site(self, addrs, max_depth=1):
        """Infer patch site address, given a tailing block address trace before an exception occurs.

        :param addrs: list of block addresses before exception (e.g., crash) occurs
        :param depth: depth of the call stack to be considered.
            0 means the direct call site (at program address space) of the abnormal site is used.
        :return: address of the function call site to be patched
        """
        reason_addr = None
        candidates = []
        depth = 0
        func_to_skip = None
        func_to_skip_size = 0  # unknown
        for addr in reversed(addrs):

            if func_to_skip is not None:
                # Find the function address in the trace
                if addr != func_to_skip:
                    continue
                else:
                    # The previous instruction should be the call instruction
                    depth += 1
                    func_to_skip_size = self._get_func_size(func_to_skip)
                    func_to_skip = None
                    continue

            if addr >= 0x3F000000:  # Address not in the executable memory space
                continue

            # Ensure the addr is in a non-library function
            func_addr = self._get_func_begin(addr)
            if self._is_lib_func(func_addr):
                continue

            # Assume the last non-library address causes the exception
            if reason_addr is None:
                reason_addr = addr

            # Find call instruction
            exit_insn = self._get_exit_insn(addr)
            if exit_insn is None:
                continue
            if not self._is_insn_call(exit_insn):
                continue

            # We may skip the function call
            exit_insn_addr = exit_insn["offset"]
            candidates.append((exit_insn_addr, reason_addr, depth, func_to_skip_size))

            if depth >= max_depth:
                break

            # The next callee function we may skip
            func_to_skip = self._get_func_begin(exit_insn_addr)

            if func_to_skip == addr:  # Already meet expectation
                func_to_skip = None

        if not candidates:
            return None

        prev_candidate = None
        for candidate in candidates:
            # HACK: avoid skipping function containing lots of code
            func_to_skip_size = candidate[3]
            if func_to_skip_size > 0x400:
                return prev_candidate if prev_candidate else candidate

            prev_candidate = candidate

        return candidates[-1]

    def _get_func_begin(self, ins_addr: int):
        """Get function begin address based on instruction address"""
        res = self.r2.cmdj(f"?j $FB @ {ins_addr}")
        return int(res["hex"], 16)

    def _get_func_size(self, func_addr: int):
        """Get function size"""
        res = self.r2.cmdj(f"?j $FS @ {func_addr}")
        return int(res["hex"], 16)

    def _is_lib_func(self, func_addr: int):
        """Check if function is from library"""
        # is imported function
        res = self.r2.cmdj(f"is.j @ {func_addr}")
        symbol = res["symbols"]
        # radare may return wrong symbol, so double check
        if not symbol or symbol["vaddr"] != func_addr:
            return False

        if symbol["type"] == "FUNC" and symbol["is_imported"]:
            return True

        # is stub call to imported function
        res = self.r2.cmdj(f"afbj @ {func_addr}")
        if res and res[0]["ninstr"] <= 3:
            return True

        return False

    def _get_exit_insn(self, block_addr: int):
        """Get address of exit instruction of QEMU translate block
        :param block_addr: address of QEMU translate block
        :return: address of exit instruction or None if not found
        """
        # QEMU translate block is different from r2 block, we need to enumerate instruction one by one
        for insn in self._enumerate_insn(block_addr):
            if (
                insn["type"].endswith("call")
                or insn["type"].endswith("jmp")
                or insn["type"].endswith("ret")
            ):
                break
        else:
            # TODO: situation that is not handled
            return None

        return insn

    def _enumerate_insn(self, block_addr: int):
        """Enumerate instructions in QEMU translate block

        :param block_addr: address of QEMU translate block
        :param end: address of the end of the block
        """
        curr_addr = block_addr
        block_end = int(self.r2.cmdj(f"?j $Fe @ {block_addr}")["hex"], 16)
        while curr_addr < block_end:
            insn = self.r2.cmdj(f"pdj 1 @ {curr_addr}")[0]
            yield insn
            curr_addr += insn["size"]

    def _get_insn_at(self, addr: int):
        """Get instruction at address"""
        return self.r2.cmdj(f"pdj 1 @ {addr}")[0]

    def _is_insn_call(self, insn):
        """Determine whether a given instruction is call"""
        if insn["type"].endswith("call"):
            return True

        if not insn["type"].endswith("jmp"):
            return False

        if "refs" not in insn:
            return False
        refs = insn["refs"]
        for ref in refs:
            if not ref["type"] == "CODE":
                continue

            ref_addr = ref["addr"]
            if self._get_func_begin(ref_addr) == ref_addr:
                return True

        # TODO: indirect call
        return False
