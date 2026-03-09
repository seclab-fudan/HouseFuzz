"""
Items module.
"""

from __future__ import annotations
import os
import tarfile


class ScanItem:
    """Abstract item class."""

    @property
    def root(self) -> str:
        """Root path of the target file."""
        raise NotImplementedError("root")

    @property
    def path(self) -> str:
        """Relative path to the target file."""
        raise NotImplementedError("path")

    @property
    def size(self) -> int:
        """Size of the target file."""
        fp = self.open()
        fp.seek(0, os.SEEK_END)
        size = fp.tell()
        fp.close()
        return size

    def open(self):
        """Return the target file object. Automatically following symbolic links."""
        raise NotImplementedError("open")

    def extract(self, path):
        """Extract the target file to a path."""
        raise NotImplementedError("extract")

    def follow_lnk(self):
        """Get the target of a symbolic link."""
        raise NotImplementedError("follow_lnk")

    def is_file(self):
        """Check if the target is a file."""
        raise NotImplementedError("is_file")

    def is_dir(self):
        """Check if the target is a directory."""
        raise NotImplementedError("is_dir")

    def is_elf(self):
        """Check if the target file is an ELF file."""
        raise NotImplementedError("is_elf")

    def is_lnk(self):
        """Check if the target is a symbolic link."""
        raise NotImplementedError("is_lnk")

    def get_abs_item(self, path) -> TarItem | None:
        """Get an item by absolute path."""
        raise NotImplementedError("get_abs_item")

    def get_rel_item(self, path) -> TarItem | None:
        """Get an item by relative path."""
        raise NotImplementedError("get_rel_item")

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, ScanItem):
            return NotImplemented
        return (self.root, self.path) == (value.root, value.path)

    def __hash__(self) -> int:
        return hash((self.root, self.path))


class FSItem(ScanItem):
    """File system item class."""

    def __init__(self, root, path) -> None:
        self._root = root
        self._path = path

    @property
    def root(self) -> str:
        return self._root

    @property
    def path(self) -> str:
        return self._path

    def open(self):
        full_path = os.path.join(self._root, self._path)
        return open(full_path, "rb")

    def extract(self, path):
        with open(path, "wb") as f:
            f.write(self.open().read())

    def follow_lnk(self):
        if self.is_lnk():
            linkname = os.readlink(self._path)
            if os.path.isabs(linkname):
                item = FSItem("/", linkname)
            else:
                item = FSItem(os.path.dirname(self._path), linkname)
            return item.follow_lnk()
        return self

    def is_file(self):
        return os.path.isfile(self._path)

    def is_dir(self):
        return os.path.isdir(self._path)

    def is_elf(self):
        if not self.is_file():
            return False
        if os.path.getsize(self._path) < 4:
            return False
        with open(self._path, "rb") as f:
            magic = f.read(4)
        return magic == b"\x7fELF"

    def is_lnk(self):
        return os.path.islink(self._path)

    def get_abs_item(self, path) -> TarItem | None:
        if path.startswith("/"):
            path = "." + path
        return FSItem(self._root, path)

    def get_rel_item(self, path) -> TarItem | None:
        return FSItem(self._root, path)


class TarItem(ScanItem):
    """Tar item class."""

    def __init__(self, tar_file: tarfile.TarFile, tar_info: tarfile.TarInfo):
        assert tar_file
        assert tar_info
        self.tar = tar_file
        self.info = tar_info

    def open(self) -> tarfile.ExFileObject:
        item = self.follow_lnk()
        assert item and item.info.isfile()
        return self.tar.extractfile(item.info)

    def extract(self, path: str):
        item = self.follow_lnk()
        assert item
        self.tar.extract(item.info, path)

    @property
    def root(self) -> str:
        return self.tar.name

    @property
    def path(self) -> str:
        return self.info.name

    def follow_lnk(self) -> TarItem:
        """Get the target of a symbolic link."""
        if self.info.issym():  # TODO: whether to also include islnk()?
            linkname = self.info.linkname
            if os.path.isabs(linkname):
                item = self.get_abs_item(linkname)
            else:
                item = self.get_rel_item(linkname)
            if item:
                return item.follow_lnk()
            else:
                # TODO: log warning
                return self
        return self

    def is_file(self):
        """Check if the target is a file."""
        return self.info.isfile()

    def is_dir(self):
        """Check if the target is a directory."""
        return self.info.isdir()

    def is_lnk(self):
        """Check if the target is a symbolic link."""
        return self.info.issym()

    def is_elf(self):
        """Check if the target file is an ELF file."""
        if not self.info.isfile():
            return False
        if self.info.size < 4:
            return False
        magic = self.open().read(4)
        return magic == b"\x7fELF"

    @classmethod
    def _tar_prefix(cls, tar: tarfile.TarFile) -> str:
        """Get the prefix of a tar file."""
        names = tar.getnames()
        names.remove(".")
        return os.path.commonprefix(names)

    @classmethod
    def _tar_join(cls, base: str, /, *paths) -> str:
        """Join a prefix and a path."""
        path = os.path.join(base, *paths)
        normpath = os.path.normpath(path)
        # normpath may remove the leading "./" in the path, so we need to add it back
        if path.startswith("./") and not normpath.startswith("./"):
            normpath = f"./{normpath}"
        return normpath

    def get_rel_item(self, path) -> TarItem | None:
        """Get a tar item by relative path.
        :param path: The relative path to the target item.
        :return: The tar item if it exists, otherwise None.
        """
        if self.info.isdir():
            path = os.path.join(self.path, path)
        else:
            dirname = os.path.dirname(self.path)
            path = self._tar_join(dirname, path)
        return self.get_abs_item(path)

    def get_abs_item(self, path, prefix=None) -> TarItem | None:
        """Get a tar item by absolute path.
        :param path: The path to the target item. It can be a name in tar or a path relative to the prefix.
        :param prefix: The prefix of the path. if not provided, it will be inferred from the tar file.
        :return: The tar item if it exists, otherwise None.
        """

        tar_paths = self.tar.getnames()
        path = str(path)
        if path in tar_paths:
            tar_info = self.tar.getmember(path)
        else:
            if not prefix:
                prefix = self._tar_prefix(self.tar)
            if not prefix:
                return None

            if path.startswith("/"):
                path = path[1:]
            path = os.path.join(prefix, path)
            if path in tar_paths:
                tar_info = self.tar.getmember(path)
            else:
                return None

        return TarItem(self.tar, tar_info)
