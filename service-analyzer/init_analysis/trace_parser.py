"""
Parse strace of qemu-user and generate a process spawn tree
"""

from __future__ import annotations
import sys
import os
import re
import tarfile
from functools import lru_cache
from dataclasses import dataclass


@dataclass
class TranslateBlock:
    """Translation block in strace log"""

    log_id: int
    pc: int


@dataclass
class SignalEvent:
    """Signal event in strace log"""

    log_id: int
    name: str  # Signal name
    line: bytes  # The log line


@dataclass
class SyscallEvent:
    """Event in strace log"""

    log_id: int
    pid: int
    name: str
    args_str: bytes
    ret: int
    error: str

    @property
    def args(self):
        """Arguments of the syscall"""
        return self._parse_args(self.args_str)

    @classmethod
    def _parse_args(cls, args_str, idx=0):
        """
        Parse arguments from argument list string
        e.g., "/sbin/brctl",{"brctl","addbr","br0",NULL}
                -> ["/sbin/brctl", {"brctl","addbr","br0",NULL}]
        """

        in_quote = False
        eval_str = ""
        for idx, c in enumerate(args_str):
            c = chr(c)
            if c == '"':
                if (
                    idx + 1 >= len(args_str)
                    or chr(args_str[idx + 1]) in [",", "}"]
                    or idx == 0
                    or chr(args_str[idx - 1]) in [",", "{"]
                ):
                    in_quote = not in_quote
                else:
                    eval_str += "\\"
                eval_str += c
            elif not in_quote and c == "{":
                eval_str += "["
            elif not in_quote and c == "}":
                eval_str += "]"
            elif not in_quote and c == "|":
                eval_str += "+'|'+"
            elif (
                not in_quote
                and c == "0"
                and (
                    idx + 1 >= len(args_str) or chr(args_str[idx + 1]) not in ["x", "X"]
                )
                and (idx == 0 or chr(args_str[idx - 1]) in [",", "}"])
            ):
                eval_str += "0o"
            else:
                eval_str += c

        try:
            env_args = _EvalDict()
            args = eval(eval_str, env_args)  # pylint: disable=eval-used
        except:  # pylint: disable=bare-except
            # print(eval_str)
            return None
        return args


class _EvalDict(dict):
    def __init__(self, *arg, **kw):
        super().__init__(*arg, **kw)

    def __getitem__(self, key):
        if key not in self:
            return key
        return self.__dict__[key]


class TraceParser:
    """Parser of qemu trace log"""

    file_limit = 10000

    re_translate_block = re.compile(
        rb"translate_block tb:(0x[0-9a-f]+), pc:(?P<pc>0x[0-9a-f]+), tb_code:(0x[0-9a-f]+)"
    )
    re_signal = re.compile(rb"--- (?P<name>\w+) {")
    re_syscall = re.compile(
        rb"(?P<pid>\d+)\s+(?P<syscall>\w+)\((?P<args>.*?)\)(\s+=\s+(?P<ret>-?(0x)?\d+)|$)(?P<error>\s+errno = .*)?"
    )
    re_syscall_error = re.compile(rb"=\s+(?P<ret>-\d+)(?P<error>\s+errno=\d+.*)")

    @classmethod
    def parse(cls, trace_path: str):
        """Parse qemu trace log and generate a process spawn tree"""
        if os.path.isdir(trace_path):
            file_paths = []
            for file_path in os.listdir(trace_path):
                if not file_path.startswith("QEMU_LOG_"):
                    continue
                file_paths.append(os.path.join(trace_path, file_path))
        else:
            file_paths = [trace_path]

        file_paths.sort(key=cls._get_log_id_from_filename)
        if cls.file_limit:
            if len(file_paths) > cls.file_limit:
                print(f"Limiting the number of files to {cls.file_limit}")
                file_paths = file_paths[: cls.file_limit]

        all_events = []
        for file_path in file_paths:
            log_id = cls._get_log_id_from_filename(file_path)
            with open(file_path, "rb") as stream:
                events, unresolved_lines = cls._parse_events(stream, log_id)
                if unresolved_lines:
                    pass
                    # print(f"Unresolved lines in {file_path}:", [l[0] for l in unresolved_lines])
                all_events.extend(events)

        trace = TraceTree.build(all_events)
        return trace

    @classmethod
    def parse_tar(cls, tar_file, ids: list[int] = None):
        """
        Parse tar file and generate a list of process dict
        
        :param tar_file: path to the tar file
        :param ids: list of log ids to parse, if empty, parse all logs
        """
        all_events = []
        with tarfile.open(tar_file, "r") as tar:
            names = tar.getnames()
            for name in names:
                basename = os.path.basename(name)
                if not basename.startswith("QEMU_LOG_"):
                    continue
                log_id = cls._get_log_id_from_filename(basename)
                if ids and log_id not in ids:
                    continue
                stream = tar.extractfile(name)
                events, _ = cls._parse_events(stream, log_id)
                all_events.extend(events)

        trace = TraceTree.build(all_events)
        return trace

    @classmethod
    def parse_ps(cls, ps_file):
        """
        Parse ps aux file and generate a list of process dict
        """
        ps_file.seek(0)

        output = ps_file.readlines()
        # convert bytes to string
        output = [line.decode() if isinstance(line, bytes) else line for line in output]
        headers = [h for h in ' '.join(output[0].strip().split()).split() if h]
        raw_data = map(lambda s: s.strip().split(None, len(headers) - 1), output[1:])
        return [dict(zip(headers, r)) for r in raw_data]


    @classmethod
    def _parse_events(cls, stream, log_id: int):
        """
        Parse strace file and generate a process spawn tree
        """

        lines = stream.readlines()

        events = []
        unresolved_lines = []
        prev_syscall_event = None

        for idx, line in enumerate(lines):
            line = line.strip()

            if cls._parse_translateblock(line, events, log_id):
                continue

            if cls._parse_syscall(line, prev_syscall_event, events, log_id):
                prev_syscall_event = events[-1]
                continue

            if cls._parse_signal(line, events, log_id):
                continue

            unresolved_lines.append((idx + 1, line))

        return events, unresolved_lines

    @classmethod
    def _parse_translateblock(cls, line, events: list, log_id: int):
        """Parse translate block event

        :return: True if the line is successfully parsed, False otherwise
        """
        # translate_block tb:0x7f2cf416a3c0, pc:0x29180, tb_code:0x7f2cf416a440
        if not line.startswith(b"translate_block"):
            return False

        mat = cls.re_translate_block.match(line)
        if not mat:
            return False

        pc = int(mat.group("pc"), 16)
        event = TranslateBlock(log_id=log_id, pc=pc)
        events.append(event)
        return True

    @classmethod
    def _parse_signal(cls, line, events: list, log_id: int):
        """Parse signal event

        :return: True if the line is successfully parsed, False otherwise
        """
        # --- SIGCHLD {si_signo=SIGCHLD, si_code=1, si_pid=763, si_uid=0, si_status=1, si_utime=8, si_stime=2} ---
        if not line.startswith(b"---"):
            return False

        mat = cls.re_signal.match(line)
        if not mat:
            return False

        name = mat.group("name").decode()
        event = SignalEvent(log_id=log_id, name=name, line=line)
        events.append(event)
        return True

    @classmethod
    def _parse_syscall(cls, line, prev_event, events: list, log_id: int):
        """Parse syscall event

        :return: True if the line is successfully parsed, False otherwise
        """
        if line.startswith(b"---"):
            return False

        mat = cls.re_syscall.match(line)
        if not mat:
            mat = cls.re_syscall_error.match(line)

            if mat:
                prev_event.ret = mat.group("ret").decode()
                prev_event.error = mat.group("error").decode()
                return True
            else:
                return False

        pid = int(mat.group("pid").decode())
        syscall = mat.group("syscall").decode()
        args_str = mat.group("args")
        ret = mat.group("ret")
        if ret:
            if b"0x" in ret:
                ret = int(ret, 16)
            else:
                ret = int(ret, 10)
        error = mat.group("error")
        if error is not None:
            error = error.decode()
        event = SyscallEvent(
            log_id=log_id,
            pid=pid,
            name=syscall,
            args_str=args_str,
            ret=ret,
            error=error,
        )
        events.append(event)
        return True

    @classmethod
    def _get_log_id_from_filename(cls, filename: str) -> int:
        """Get log id from filename"""
        return int(filename.rsplit("_", 1)[-1])


class TraceNode:
    """Node in process spawn tree"""

    def __init__(self, pid, tree):
        self.pid = pid
        self.tree = tree
        self.events = list()

    @property
    def syscalls(self):
        """Get syscalls of the process"""
        for event in self.events:
            if isinstance(event, SyscallEvent):
                yield event
    
    @property
    def translate_blocks(self):
        """Get translate blocks of the process"""
        for event in self.events:
            if isinstance(event, TranslateBlock):
                yield event

    def add_event(self, event):
        """Add a child process to the process spawn tree"""
        self.events.append(event)

    def get_events(self):
        """Get events of the process"""
        return self.events

    @lru_cache(maxsize=2)
    def get_cmdline(self) -> str:
        """Get command of the process"""
        for event in reversed(self.events):
            # Heuristic the final sucessful execve syscall
            if isinstance(event, SyscallEvent) and event.name == "execve" and event.pid == self.pid:
                break
        else:
            # This is a forked process, use cmdline of its parent
            ppid = self.tree.get_parent(self.pid)
            if not ppid:
                return "<Unknown>"
            parent = self.tree.get_node(ppid)
            return parent.get_cmdline()

        if not event.args:
            return "<Unresolved>"

        cmdline = event.args[0] + " " + " ".join(event.args[1][1:-1])
        return cmdline


class TraceTree:
    """Process spawn tree"""

    def __init__(self) -> None:
        self.p2c = {}  # parent to children
        self.c2p = {}  # children to parent
        self.nodes = {0: TraceNode(0, self)}  # pid to node

    def add_node(self, pid):
        """Add a node to the process spawn tree"""
        if pid in self.nodes:
            return self.nodes[pid]

        node = TraceNode(pid, self)
        self.nodes[pid] = node
        return node

    def get_node(self, pid):
        """Get a node by pid"""
        return self.nodes.get(pid, None)

    def add_edge(self, parent_pid, child_pid):
        """Add an edge to the process spawn tree"""
        if parent_pid not in self.p2c:
            self.p2c[parent_pid] = []
        self.p2c[parent_pid].append(child_pid)

        if child_pid not in self.c2p:
            self.c2p[child_pid] = []
        self.c2p[child_pid].append(parent_pid)

    def get_parent(self, pid):
        """Get parent of a process"""
        parent = self.c2p.get(pid, None)
        if parent is None:
            return None
        return parent[0]

    def get_children(self, pid):
        """Get children of a process"""
        return self.p2c.get(pid, None)

    def get_ancestors(self, pid):
        """Get ancestors of a process"""
        ancestors = []
        while pid != 0:
            if not self.get_parent(pid):  # 0 or None
                break
            pid = self.get_parent(pid)
            ancestors.append(pid)
        return ancestors

    def get_descendants(self, pid):
        """Get descendants of a process"""
        descendants = []
        if pid not in self.p2c:
            return descendants
        for child in self.p2c[pid]:
            descendants.append(child)
            descendants.extend(self.get_descendants(child))
        return descendants

    def get_path(self, from_pid, to_pid):
        """Get path between two processes, including the two processes themselves"""
        if from_pid == to_pid:
            return [self.get_node(from_pid)]
        if (
            from_pid not in self.nodes
            or to_pid not in self.nodes
            or from_pid == 0
            or to_pid == 0
        ):
            return None

        # use reverse dfs to find the path from to_pid to from_pid with c2p
        def dfs(from_pid, to_pid, path):
            if to_pid == 0:
                return None
            if from_pid in self.c2p[to_pid]:
                return [from_pid] + path

            for parent_pid in self.c2p.get(to_pid, []):
                new_path = dfs(from_pid, parent_pid, [parent_pid] + path)
                if new_path:
                    return new_path
            return None

        path = dfs(from_pid, to_pid, [])
        if path:
            path = [self.get_node(pid) for pid in path]
        return path

    def get_distance(self, from_pid, to_pid):
        """Get distance between two processes"""
        path = self.get_path(from_pid, to_pid)
        if not path:
            return None
        return len(path) - 1

    def format(self):
        """Format process spawn tree using ASCII art"""

        def format_node(pid, level, mark):
            node = self.get_node(pid)
            if not node:
                return ""
            command = node.get_cmdline()
            if not command:
                command = "<Unresolved>"
            if not level:
                prefix = ""
            else:
                prefix = "   " * (level - 1) + mark
            lines = [f"{prefix} {pid}: {command}"]
            children = self.get_children(pid)
            if children:
                level += 1
                for idx, child in enumerate(children):
                    if idx == len(children) - 1:
                        lines.append(format_node(child, level, " └─"))
                    else:
                        if self.get_children(child):
                            lines.append(format_node(child, level, " └─"))
                        else:
                            lines.append(format_node(child, level, " ├─"))

                        # lines.append(
                        #     format_node(child, prefix + "   ")
                        # )
            return "\n".join(lines)

        return format_node(0, 0, "")

    @classmethod
    def build(cls, events: list[SyscallEvent]):
        """
        Build process spawn tree from strace events
        """

        pst = TraceTree()

        for event in events:

            if hasattr(event, "pid"):
                node_id = event.pid
            elif hasattr(event, "log_id"):
                node_id = event.log_id
            else:
                raise ValueError(f"Unknown event type: {event}")

            node = pst.get_node(node_id)

            if not node:
                node = pst.add_node(node_id)
            node.add_event(event)

            if pst.get_parent(node_id) is None:
                pst.add_edge(0, node_id)

            if isinstance(event, SyscallEvent) and (
                event.name == "fork" or event.name == "clone"
            ):
                child_pid = event.ret
                if child_pid > 0:
                    pst.add_edge(event.pid, child_pid)

        return pst


def main():
    """Main function"""
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <strace log file/dir>")
        sys.exit(1)

    TraceParser.parse(sys.argv[1])


if __name__ == "__main__":
    main()
