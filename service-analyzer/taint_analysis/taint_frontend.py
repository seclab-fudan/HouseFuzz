"""
Frontend for taint analysis
"""

import sys
import os
import logging
import resource
import traceback
import json
import re
from argparse import ArgumentParser

import angr

from .coretaint import CoreTaint
from .utils import arg_reg_names
from . import summary_functions as sf


class TaintAnalysis:
    """
    Taint analysis.
    """

    OPT_LOOP_LIMIT = 3
    OPT_MAX_RET_STOP = 10

    def __init__(self, bin_path: str, base_addr: int):
        self._glob_setting_done = False

        self.bin_path = bin_path

        main_opts = {"base_addr": base_addr}
        self.proj = angr.Project(
            bin_path,
            auto_load_libs=False,
            main_opts=main_opts,
        )

    def run(
        self,
        entry_addr: int,
        source_info: dict,
        sink_info: dict,
        conc_regs: dict,
        black_list: list=[],
        max_depth=5,
        log=None,
        memlim=0,
        timeout=0,
        hook_before_run=None,
    ):
        """
        Run taint analysis

        :param entry_addr: entry address
        :param conc_regs: concrete registers

        :param log: log object
        :param memlim: memory limit in GB
        :param timeout: timeout
        :param hook_before_run: hook to setup ct and state before running
        """
        self.glob_setting()

        log = logging.getLogger("TaintAnalysis") if not log else log

        ct = CoreTaint(
            self.proj,
            interfunction_level=max_depth,
            smart_call=True,
            follow_unsat=True,
            black_calls=[],
            white_calls=[],
            black_list=black_list,
            try_thumb=True,
            shuffle_sat=True,
            exit_on_decode_error=True,
            force_paths=True,
            taint_returns_unfollowed_calls=True,
            allow_untaint=False,
            taint_dyn_infer=False,
            stop_on_vuln=False,
            logger_obj=log,
            path_limit=100,
            fine_taint_check=True,
            sym_global=True,
            opt_ret_merge=True,
            opt_loop_limit=self.OPT_LOOP_LIMIT,
            opt_max_ret_stop=self.OPT_MAX_RET_STOP,
            opt_taint_exit_guard=True,
            fine_recording=False,
            pending_explore=True,
        )

        state = ct.get_initial_state(entry_addr)
        # Set some registers to concrete values. This is usually
        # neccessary for mips architecture to identify .got call
        for reg, val in conc_regs.items():
            setattr(state.regs, reg, val)

        # ct.add_var(key, val, essential=True)

        # setup input summarized functions
        finish_on_call_addrs_hit = True
        si_call_addrs_hit = {}
        for si in source_info:
            si_type = si["type"]

            finish_on_call_addrs_hit = (
                finish_on_call_addrs_hit and si_type == "by_call_addr"
            )

            if si_type == "by_func_addr":
                sum_f_addr = si["addr"]
            elif si_type == "by_func_name":
                sum_f_name = si["name"]
                sum_f_addr = self.proj.loader.main_object.get_symbol(
                    sum_f_name
                ).rebased_addr
            elif si_type == "by_call_addr":
                sum_f_addr = si["addr"]
                si_call_addrs_hit[sum_f_addr] = False
            else:
                assert False, f"Unknown source info type {si_type}"
            sum_f = sf.add_taints_for_string(si.get("taint_positions"))
            ct.add_sum_f(sum_f_addr, sum_f)

        results = []

        def _check_sink(current_path, *_, ct: CoreTaint = None, **__):
            state = ct.get_state(current_path)
            if not state.info.func:  # this ignore the dummy entry state
                return False

            start_addr = state.addr
            try:
                block = state.block()
            except angr.SimEngineError:
                return False
            end_addr = start_addr + block.size

            for si in sink_info:

                taint_positions = si.get("taint_positions", [])
                if not taint_positions:
                    return False

                si_type = si["type"]
                if si_type == "by_call_addr":
                    sink_call_addr = si["addr"]
                    if state.callstack.call_site_addr != sink_call_addr:
                        continue
                    sink_func_addr = state.addr

                    # Check if all sink call addrs are hit, and stop running if so
                    si_call_addrs_hit[sink_call_addr] = True
                    if finish_on_call_addrs_hit and all(si_call_addrs_hit.values()):
                        ct.stop_run()

                elif si_type in ("by_func_name", "by_func_addr"):
                    if si_type == "by_func_name":
                        sink_name = si["name"]
                        if ct.get_func_name_by_addr(start_addr) == sink_name:
                            sink_func_addr = start_addr
                        else:
                            continue
                    else:
                        sink_func_addr = si["addr"]
                    if sink_func_addr != state.addr:
                        continue
                    sink_call_addr = state.callstack.call_site_addr
                else:
                    assert False, f"Unknown sink info type {si_type}"

                # print("Hit sink", hex(sink_addr))
                extract_string_positions = si.get("extract_string_positions", [])
                extract_integer_positions = si.get("extract_integer_positions", [])

                # check taint
                reg_names = arg_reg_names(ct.p)
                for tp in taint_positions:
                    assert tp >= 0 and tp < len(reg_names)
                    reg_name = reg_names[tp]
                    reg_val = getattr(state.regs, reg_name)
                    reg_mem_val = ct.get_state(current_path).memory.load(reg_val, 4)
                    for val in (reg_val, reg_mem_val):
                        if ct.is_tainted(val):
                            tags = ct.get_taint_tags(val)
                            source_call_addrs = []
                            source_keys = []
                            for tag in tags:
                                for mat in re.finditer(
                                    r"source_@(?P<key>[^@]+)@(?P<source_block_start>[^@]+)-(?P<source_block_end>[^@]+)@(?P<reg>[^@]+)",
                                    tag,
                                ):
                                    key = mat.group("key")
                                    source_block_start = int(
                                        mat.group("source_block_start"), 16
                                    )
                                    source_block_end = int(
                                        mat.group("source_block_end"), 16
                                    )
                                    source_call_addr = (
                                        source_block_start,
                                        source_block_end,
                                    )
                                    if source_call_addr in source_call_addrs:
                                        continue
                                    source_keys.append(key)
                                    source_call_addrs.append(source_call_addr)

                            sink_strings = {}
                            for pos in extract_string_positions:
                                if pos >= 0 and pos < len(reg_names):
                                    reg_name = reg_names[pos]
                                    val = getattr(state.regs, reg_name)
                                    s = ct.safe_load_str(current_path, val)
                                    if not s:
                                        continue
                                    try:
                                        s = s.decode("utf-8", errors="ignore")
                                    except UnicodeDecodeError:
                                        continue
                                    sink_strings[pos] = s

                            sink_integers = {}
                            for pos in extract_integer_positions:
                                if pos >= 0 and pos < len(reg_names):
                                    reg_name = reg_names[pos]
                                    val = getattr(state.regs, reg_name)
                                    val, sym = ct.resolve_val(
                                        current_path, val, keep_sym=True
                                    )
                                    if sym:
                                        pot_vals = state.solver.eval_upto(val, 2)
                                        if len(pot_vals) != 1:
                                            continue
                                    sink_integers[pos] = val

                            result = {
                                "source_keys": source_keys,
                                "source_call_addrs": source_call_addrs,
                                "sink_call_addr": sink_call_addr,
                                "sink_func_addr": sink_func_addr,
                                "sink_func_name": ct.get_func_name_by_addr(
                                    sink_func_addr
                                ),
                                "sink_strings": sink_strings,
                            }
                            results.append(result)
                            ct.log.info(
                                f"Found sink call at {sink_call_addr:#x} tags: {tags}"
                            )

                            return True

            return False

        # hook summarized functions by names
        ct.prepare_summarized_functions()

        # may add extra logic
        if hook_before_run:
            hook_before_run(ct, state)

        try:
            if memlim:
                _, hard = resource.getrlimit(resource.RLIMIT_AS)
                resource.setrlimit(
                    resource.RLIMIT_AS, (memlim * 1024 * 1024 * 1024, hard)
                )

            if timeout:
                ct.set_alarm(timeout, n_tries=3)

            ct.run(
                state,
                (),
                (),
                summarized_f={},
                force_thumb=False,
                check_func=_check_sink,
                init_bss=False,
                use_smart_concretization=False,
            )

            ct.log_summary()
        except KeyboardInterrupt:
            log.warning("Keyboard interruptted")
            sys.exit(0)
        except MemoryError:
            assert memlim
            _, hard = resource.getrlimit(resource.RLIMIT_AS)
            # enlarge memory limit for error handling
            resource.setrlimit(
                resource.RLIMIT_AS, (2 * memlim * 1024 * 1024 * 1024, hard)
            )
            ct.paths.clear()
            log.warning("Memory error")
        except Exception:
            log.warning(traceback.format_exc())

        # get result

        return ct, results

    def glob_setting(self):
        """
        Setup some resource limitations and log settings for
        replay execution
        """
        if self._glob_setting_done:
            return
        sys.setrecursionlimit(0x100000)
        sys.set_int_max_str_digits(10000)

        # disable angr logging
        logging.getLogger("angr").setLevel(logging.CRITICAL)
        logging.getLogger("cle").setLevel(logging.CRITICAL)
        logging.getLogger("pyvex").setLevel(logging.CRITICAL)
        logging.getLogger("pyvex.lifting.libvex").setLevel(logging.CRITICAL)
        # angr.loggers.disable_root_logger()
        # angr.logging.disable(logging.ERROR)

        self._glob_setting_done = True


def _err_exit(message, outfp=None):
    if outfp:
        json.dump({"status": "error", "message": message}, outfp)
    exit(1)


def _main():
    parser = ArgumentParser()
    parser.add_argument("inp_file", help="Input file")
    parser.add_argument("-o", "--out_file", help="Output file", required=True)
    parser.add_argument("-d", "--max_depth", type=int, default=5, help="Max depth")
    parser.add_argument(
        "-m", "--memlim", type=int, default=0, help="Memory limit in GB"
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=0, help="Timeout in seconds"
    )
    args = parser.parse_args()

    out_dir = os.path.dirname(args.out_file)
    os.makedirs(out_dir, exist_ok=True)
    out_file = open(args.out_file, "w+", encoding="utf-8")

    if not os.path.isfile(args.inp_file):
        _err_exit("Input file not found", out_file)

    with open(args.inp_file, "r", encoding="utf-8") as fp:
        try:
            task = json.load(fp)
        except json.JSONDecodeError:
            _err_exit("Fail to parsing json from input file", out_file)

    binary_path = task["binary_path"]
    if not os.path.isfile(binary_path):
        _err_exit(f"Binary file {binary_path} not found", out_file)

    base_addr = task["base_addr"]
    entry_addr = task["entry_addr"]

    source_info = task.get("source_info") or task.get("sources_info")
    if not source_info:
        _err_exit("No source info found", out_file)

    sink_info = task["sink_info"] or task["sinks_info"]
    if not sink_info:
        _err_exit("No sink info found", out_file)
        
    black_list = task.get("blacklist", [])

    conc_regs = task.get("conc_regs", {})

    ta = TaintAnalysis(binary_path, base_addr)

    log = logging.getLogger("TaintAnalysis")
    log_file_path = args.out_file + ".log"
    if os.path.exists(log_file_path):
        os.remove(log_file_path)
    log.addHandler(logging.FileHandler(log_file_path))
    log.setLevel(logging.DEBUG)

    _, results = ta.run(
        entry_addr,
        source_info,
        sink_info,
        conc_regs,
        black_list=black_list,
        max_depth=args.max_depth,
        log=log,
        memlim=args.memlim,
        timeout=args.timeout,
        hook_before_run=None,
    )
    log.info("Results: %s", json.dumps(results, indent=2))
    json.dump(results, out_file)
    out_file.close()


if __name__ == "__main__":
    _main()
