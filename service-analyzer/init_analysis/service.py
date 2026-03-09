from dataclasses import dataclass


@dataclass
class Service:
    """Data model for a service"""

    entry_cmd: str
    netbind_cmd: str
    local_bindings: list
    remote_bindings: list
    dep_cmds: list  # List of dependent commands

    def to_dict(self):
        """Convert the object to a dictionary"""
        return {
            "entry_cmd": self.entry_cmd,
            "netbind_cmd": self.netbind_cmd,
            "local_bindings": list(self.local_bindings),
            "remote_bindings": list(self.remote_bindings),
            "dep_cmds": list(self.dep_cmds),
        }
