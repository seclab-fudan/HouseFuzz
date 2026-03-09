"""
Analyze qemu trace to infer service information
"""

import os
import re
import logging
from itertools import groupby

from .trace_parser import TraceTree, SyscallEvent, TranslateBlock
from .service import Service

KNOWN_PORTS = {
    80: "http",
    443: "https",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    110: "pop3",
    143: "imap",
    389: "ldap",
    636: "ldaps",
    1900: "upnp",
}

POTENTIAL_PROXIED_PORTS = {80}


class TraceAnalyzer:
    """Analyze qemu trace to infer service information"""

    def __init__(self, trace: TraceTree, log=None) -> None:
        self._trace = trace
        if not log:
            log = logging.getLogger(__name__)
            log.setLevel(logging.INFO)
            log.addHandler(logging.StreamHandler())
        self.log = log

    def run(self, r2=None, infer_entry=False):
        """Analyze qemu trace to infer service information"""

        services = []
        binding_info, global_binding_info = self._infer_binding_info()
        self.log.debug("Binding info: %s", binding_info)

        if not binding_info:
            return services, binding_info

        # TODO: this branch is deprecated, remove it
        if infer_entry and r2:
            self.log.warning("Infer entry is deprecated")
            command_based_binding_info = {}
            function_based_binding_info = {}

            init_pid = 1
            for pid, binding in binding_info.items():
                if init_pid == self._trace.get_parent(pid):
                    function_based_binding_info[pid] = binding
                else:
                    command_based_binding_info[pid] = binding

            # Try to infer function-based services
            if function_based_binding_info and r2:
                if len(function_based_binding_info) > 1:
                    function_based_services = self._infer_function_based_services(
                        init_pid, function_based_binding_info, r2
                    )
                    services.extend(function_based_services)

            # Try to infer command-based services
            if command_based_binding_info:
                if len(command_based_binding_info) > 1:
                    command_based_services = self._infer_command_based_services(
                        command_based_binding_info
                    )
                    services.extend(command_based_services)

        else:
            # This is the actual implementation of service inference
            services = self._infer_services(binding_info)

        return services, global_binding_info

    def _infer_services(self, binding_info):
        services = []

        binding_addr_pid_map = {}
        for pid, bindings in binding_info.items():
            for curr_bindings in bindings.values():
                for binding in curr_bindings:
                    addr = self.get_sockaddr_identifier(binding)
                    binding_addr_pid_map.setdefault(addr, []).append(pid)

        # Infer dependencies by connections to IPC channels
        for pid, bindings in binding_info.items():
            if not bindings.get("remote") and not bindings.get("proxied"):
                continue

            netbind_node = self._trace.get_node(pid)
            cmd = netbind_node.get_cmdline()

            # Infer dependencies by connection to daemons
            deps = []
            connection_info = self._identify_network_connection(netbind_node)
            for connection in connection_info:
                # print(cmd, connection)
                connect_addr = self.get_sockaddr_identifier(connection)
                if connect_addr in binding_addr_pid_map:
                    deps.extend(
                        [
                            self._trace.get_node(x).get_cmdline()
                            for x in binding_addr_pid_map.get(connect_addr, [])
                        ]
                    )

            service = Service(
                entry_cmd=cmd,
                netbind_cmd=cmd,
                local_bindings=bindings["local"],
                remote_bindings=bindings["remote"] + bindings["proxied"],
                dep_cmds=deps,
            )
            services.append(service)

        # Merge services with the same entry_cmd
        new_services = []
        for _, group in groupby(services, key=lambda x: x.entry_cmd):
            group = list(group)
            service = group[0]
            if len(group) > 1:
                for other_service in group[1:]:
                    service.local_bindings.extend(other_service.local_bindings)
                    service.remote_bindings.extend(other_service.remote_bindings)
                    service.dep_cmds.extend(other_service.dep_cmds)
            new_services.append(service)
        services = new_services

        # Deduplicate
        def deduplicate_bindings(bindings):
            seen = set()
            return [
                x
                for x in bindings
                if not (self.get_sockaddr_identifier(x) in seen or seen.add(self.get_sockaddr_identifier(x)))
            ]
        for service in services:
            seen = set()
            service.local_bindings = deduplicate_bindings(service.local_bindings)
            service.remote_bindings = deduplicate_bindings(service.remote_bindings)
            service.dep_cmds = list(set(service.dep_cmds))

        return services

    def _infer_function_based_services(self, init_pid, binding_info, r2):
        init_node = self._trace.get_node(init_pid)
        events = init_node.events

        ranges = self._split_events_ranges(events, binding_info.keys())
        events_by_pid = self._infer_events_by_pid(r2, events, ranges)
        deps_by_pid = {
            pid: self._infer_deps_from_events(events)
            for pid, events in events_by_pid.items()
        }

        services = []
        for pid, binding in binding_info.items():
            netbind_node = self._trace.get_node(pid)
            cmd = netbind_node.get_cmdline()
            deps = list(set(deps_by_pid.get(pid, [])))
            service = Service(
                entry_cmd=cmd,
                netbind_cmd=cmd,
                local_bindings=binding["local"],
                remote_bindings=binding["remote"] + binding["proxied"],
                dep_cmds=deps,
            )
            services.append(service)

        return services

    def _split_events_ranges(self, events, pids):
        spawn_sites = []
        for event_idx, event in enumerate(events):
            if isinstance(event, SyscallEvent) and (
                event.name == "fork" or event.name == "clone"
            ):
                child_pid = event.ret
                if child_pid in pids:
                    assert child_pid not in spawn_sites
                    spawn_sites.append((child_pid, event_idx))

        if not spawn_sites:
            return []

        ranges = []
        for idx, (pid, _) in enumerate(spawn_sites):
            if idx == 0:
                start_idx = spawn_sites[idx][1] + 1
                end_idx = spawn_sites[idx + 1][1]
            else:
                start_idx = spawn_sites[idx - 1][1] + 1
                end_idx = spawn_sites[idx][1]
            ranges.append((pid, start_idx, end_idx, idx == 0))

        return ranges

    def _infer_events_by_pid(self, r2, events, ranges):
        def get_fn(site):
            r2res = r2.cmdj(f"?j $FB @ {site}")
            if not r2res:
                return None
            offset = int(r2res["hex"], 16)
            name = r2.cmd(f"afn @ {offset}").strip()
            return name, offset

        events_by_pid = {}
        for pid, start_idx, end_idx, is_first in ranges:
            called_fns = set()
            for event in events[start_idx:end_idx]:
                if not isinstance(event, TranslateBlock):
                    continue
                addr = event.pc
                if addr >= 0x3F000000:
                    continue

                fn = get_fn(addr)
                called_fns.add(fn)

            # Find out the top functions
            not_top = set()
            for name, offset in called_fns:
                cg = r2.cmdj(f"agcj @ {offset}")
                if not cg:
                    not_top.add(name)
                    continue
                cg = cg[0]
                callee_names = cg["imports"]
                not_top.update(callee_names)

            not_top = {get_fn(x) for x in not_top}
            top_fns = called_fns - not_top

            if not top_fns:
                continue

            if is_first:
                service_event_start = 0
                service_events = events[:start_idx]
            else:
                service_event_start = start_idx
                service_events = events[start_idx:end_idx]

            # Determine service event scope
            for idx, event in enumerate(service_events):
                if not isinstance(event, TranslateBlock):
                    continue
                addr = event.pc
                if addr >= 0x3F000000:
                    continue
                fn = get_fn(addr)
                if fn in top_fns:
                    if len(top_fns) == 1:
                        events_by_pid[pid] = events[service_event_start + idx : end_idx]
                        break
                    else:
                        if is_first:
                            events_by_pid[pid] = events[
                                service_event_start + idx : start_idx
                            ]
                        top_fns.remove(fn)
        return events_by_pid

    def _infer_command_based_services(self, binding_info):

        # find common patterns
        arg0_whitelist = self._get_arg0_whitelist(binding_info)
        clusters = self._cluster_nodes_by_commands(
            self._trace.nodes.values(), arg0_whitelist
        )

        self.log.info(
            "Command Clusters: %s",
            [[node.get_cmdline() for node in cluster] for cluster in clusters],
        )

        service_entries = self._infer_service_entries_by_command_clusters(
            clusters, binding_info
        )
        service_deps = self._infer_command_based_service_dependencies(service_entries)

        services = []
        for pid, binding in binding_info.items():
            netbind_node = self._trace.get_node(pid)
            entry_node = service_entries.get(pid, netbind_node)
            deps = service_deps.get(pid, [])
            service = Service(
                entry_cmd=entry_node.get_cmdline(),
                netbind_cmd=netbind_node.get_cmdline(),
                local_bindings=binding["local"],
                remote_bindings=binding["remote"] + binding["proxied"],
                dep_cmds=deps,
            )
            services.append(service)

        return services

    def _infer_deps_from_events(self, events):
        deps = []

        def is_nvram_access(target):
            return target and target.startswith("/gh_nvram")

        def get_nvram_key(target):
            if not is_nvram_access(target):
                return None
            key = target[len("/gh_nvram/") :]
            if not key:
                return None
            return key

        file_op0_list = ["open", "creat", "access", "stat", "lstat", "chdir", "mkdir"]
        file_op1_list = ["openat", "openat2", "faccessat", "faccessat2"]
        for event in events:
            if not isinstance(event, SyscallEvent):
                continue
            if event.name == "execve":
                deps.append(
                    "execve: " + event.args[0] + " " + " ".join(event.args[1][1:-1])
                )
                continue

            if event.name in file_op0_list or event.name in file_op1_list:
                if not event.args:
                    print(event.args_str)
                    continue

                if event.name in file_op0_list:
                    target = event.args[0]
                else:
                    target = event.args[1]

                if not is_nvram_access(target) and "/lib" not in target:
                    deps.append(f"{event.name}: {event.args[0]}")
                # else:
                #     key = get_nvram_key(target)
                #     if key:
                #         deps.append(f"nvram: {key}")
        return deps

    def _infer_binding_info(self):
        binding_info = {}
        global_binding_info = {
            "remote": {},
            "local": {},
        }

        bindings = self._identify_bindings()
        if not bindings:
            return binding_info, global_binding_info

        for pid, pid_bindings in bindings.items():
            if not pid_bindings:
                continue

            remote_bindings, proxied_bindings, local_bindings = self._filter_bindings(
                pid_bindings
            )
            target_bindings = remote_bindings + proxied_bindings

            process_node = self._trace.get_node(pid)
            cmdline = process_node.get_cmdline()
            if cmdline and not cmdline.startswith("<"):
                if target_bindings:
                    global_binding_info["remote"].setdefault(cmdline, []).extend(
                        target_bindings
                    )
                if local_bindings:
                    global_binding_info["local"].setdefault(cmdline, []).extend(
                        local_bindings
                    )

            binding_info[pid] = {
                "remote": remote_bindings,
                "proxied": proxied_bindings,
                "local": local_bindings,
            }

        return binding_info, global_binding_info

    def _identify_network_connection(self, node):
        """Identify all IPC syscall for local network targets"""

        connections = []

        for event in node.syscalls:
            if event.name in ("connect", "sendto"):
                connection_target = self.get_sockaddr(event)
                if connection_target:
                    connections.append(connection_target)
            elif event.name == "sendmsg":
                # TODO: handle sendmsg
                pass

        return connections

    def _identify_bindings(self):
        """Identify network binding process

        :return: pid and the binding targets
        """

        results = {}
        if not self._trace:
            return results

        for pid, node in self._trace.nodes.items():
            for event in node.syscalls:
                if event.name != "bind":
                    continue
                binding_target = self.get_sockaddr(event)
                if binding_target:
                    results.setdefault(pid, []).append(binding_target)

        return results

    @classmethod
    def get_sockaddr(cls, event):
        """Get sockaddr information from syscall event"""
        assert isinstance(event, SyscallEvent)

        # 321 bind(3,{sin_family=AF_INET,sin_port=htons(80),sin_addr=inet_addr("0.0.0.0")}, 16) = 0
        patterns = [
            r'sun_family=(?P<family>AF_UNIX),sun_path="(?P<sun_path>.*)"',
            r'sin_family=(?P<family>AF_INET),sin_port=htons\((?P<port>-?\d+)\),sin_addr=inet_addr\("(?P<addr>[\d\.]+)"\)',
            r'sin6_family=(?P<family>AF_INET6),sin6_port=htons\((?P<port>-?\d+)\),sin6_addr=inet_addr\("(?P<addr>[\da-fA-F\.:]+)"\)',
            r"sll_family=(?P<family>AF_PACKET),sll_protocol=htons\((?P<protocol>0x[0-9a-fA-F]+)\),if(?P<ifindex>\d+),pkttype=(?P<pkttype>\w+),sll_addr=(?P<addr>[\w:]+)",
            r"nl_family=(?P<family>AF_NETLINK),nl_pid=(?P<pid>\d+),nl_groups=(?P<groups>\d+)",
            r"sa_family=(?P<family>%d), sa_data=(?P<data>\{[0-9a-fA-F, ]+\})",
        ]
        args_str = event.args_str.decode(encoding="utf-8", errors="ignore")
        for pattern in patterns:
            mat = re.search(pattern, args_str)
            if mat:
                return mat.groupdict()

        return {"family": "UNKNOWN", "data": args_str}

    @classmethod
    def get_sockaddr_identifier(cls, addr):
        """Get identifier from sockaddr information"""
        if not addr or "family" not in addr:
            return None

        if addr["family"] == "AF_INET":
            return f"AF_INET:{addr.get('addr')}:{addr.get('port')}"

        if addr["family"] == "AF_INET6":
            return f"AF_INET:{addr.get('addr')}:{addr.get('port')}"

        if addr["family"] == "AF_UNIX":
            return f"AF_UNIX:{addr.get('sun_path')}"

        if addr["family"] == "AF_PACKET":
            return f'AF_PACKET:{addr.get("protocol")}:{addr.get("ifindex")}:{addr.get("pkttype")}:{addr.get("addr")}'

        if addr["family"] == "AF_NETLINK":
            return f"AF_NETLINK:{addr.get('pid')}:{addr.get('groups')}"

        return f'{addr["family"]}:{addr["data"]}'

    def _filter_bindings(self, bindings):
        remote_bindings = []
        local_bindings = []
        proxied_bindings = []
        for binding in bindings:
            if (
                not binding.get("family").startswith(
                    "AF_INET"
                )  # either AF_INET or AF_INET6
                or "addr" not in binding
                or binding["addr"] == "127.0.0.1"
            ):
                if "port" in binding:
                    port = int(binding["port"])
                    if port in POTENTIAL_PROXIED_PORTS:
                        proxied_bindings.append(binding)
                        continue
                local_bindings.append(binding)
            else:
                remote_bindings.append(binding)

        return remote_bindings, proxied_bindings, local_bindings

    def _get_arg0_whitelist(self, binding_info):
        node_arg0_whitelist = set()
        for pid in binding_info:
            ancestor_pids = [pid] + self._trace.get_ancestors(pid)
            for ancestor_pid in ancestor_pids:
                cmdline = self._trace.get_node(ancestor_pid).get_cmdline()
                arg0 = cmdline.split(" ")[0]
                if arg0.startswith("<"):
                    continue
                node_arg0_whitelist.add(arg0)
        return node_arg0_whitelist

    def _cluster_nodes_by_commands(self, nodes, arg0_whitelist: set):
        clusters = []

        def to_vec(node):
            cmdline = node.get_cmdline()
            if not cmdline:
                return None
            vec = [x for x in re.split(r"\s+|/", cmdline) if x]
            if len(vec) <= 2:
                return None
            return vec

        def is_vec_valid(vec):
            if not vec:
                return False
            if vec[0].startswith("<"):
                return False
            return True

        def node_sim(node1, node2):
            vec1 = to_vec(node1)
            vec2 = to_vec(node2)

            if not vec1 or not vec2:
                return False

            if vec1 == vec2:
                return True

            if _edit_distance(vec1, vec2) < 3:
                return True

        for node in nodes:
            vec = to_vec(node)
            if not is_vec_valid(vec):
                continue

            arg0 = node.get_cmdline().split()[0]
            if arg0 not in arg0_whitelist:
                continue

            if not clusters:
                clusters.append([node])
                continue

            for cluster in clusters:
                for cluster_node in cluster:
                    if not node_sim(node, cluster_node):
                        break
                else:
                    cluster.append(node)
                    break
            else:
                clusters.append([node])

        clusters = [cluster for cluster in clusters if len(cluster) > 1]
        return clusters

    def _infer_service_entries_by_command_clusters(self, clusters, binding_info):
        filtered_clusters = []
        for cluster in clusters:
            for node in cluster:
                cmdline = node.get_cmdline()
                if "rcS" in cmdline or "preinit" in cmdline:
                    break
            else:
                filtered_clusters.append(cluster)

        service_entries = {}

        for pid in binding_info:
            max_distance = 0
            found_node = None
            for cluster in filtered_clusters:
                for node in cluster:
                    distance = self._trace.get_distance(node.pid, pid)
                    if distance and distance > max_distance:
                        max_distance = distance
                        found_node = node

            if not found_node:
                self.log.warning("No service entry found for %d", pid)
                continue

            service_entries[pid] = found_node

        return service_entries

    def _infer_command_based_service_dependencies(self, service_entries):
        service_deps = {}

        for pid, entry_node in service_entries.items():
            binding_node = self._trace.get_node(pid)
            # from entry_node to binding_node
            dep_nodes = self._trace.get_path(entry_node.pid, binding_node.pid)
            if not dep_nodes:
                continue
            dep_nodes = dep_nodes[:-1]

            events = []
            for node in dep_nodes:
                events.extend(node.events)

            deps = self._infer_deps_from_events(events)
            service_deps[pid] = deps

        return service_deps


def _edit_distance(t1, t2):
    # DP problem
    len1 = len(t1)
    len2 = len(t2)
    dp = [[i + j for j in range(len2 + 1)] for i in range(len1 + 1)]
    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            if t1[i - 1] == t2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                insert = dp[i][j - 1]
                delete = dp[i - 1][j]
                replace = dp[i - 1][j - 1]
                dp[i][j] = min(insert, delete, replace) + 1
    return dp[-1][-1]
