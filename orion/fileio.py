"""Descriptor-based reads shared by resources and private control documents.

On POSIX every directory component is opened without following symlinks. On
platforms without dir_fd, reparse/symlink and identity checks are best effort;
the operator must still deny untrusted writers to the published/control tree.
"""
from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO


def is_link(path: Path) -> bool:
    """Recognize symlinks and Windows reparse points, including junctions."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


@contextmanager
def open_regular(path: str | Path, *, single_link: bool = False) -> Iterator[BinaryIO]:
    """Open one regular file without following path-component symbolic links."""
    absolute = Path(os.path.abspath(path))
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    directory: int | None = None
    descriptor: int | None = None
    try:
        if os.name == "posix" and os.open in os.supports_dir_fd:
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            directory = os.open(absolute.anchor, directory_flags)
            for component in absolute.parts[1:-1]:
                child = os.open(component, directory_flags, dir_fd=directory)
                os.close(directory)
                directory = child
            descriptor = os.open(absolute.name, flags, dir_fd=directory)
        else:
            if any(is_link(part) for part in (absolute, *absolute.parents)):
                raise ValueError("symbolic links and reparse points are not allowed")
            initial = absolute.stat()
            descriptor = os.open(absolute, flags)
            opened = os.fstat(descriptor)
            if (initial.st_dev, initial.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError("file identity changed while opening")
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("input must be a regular file")
        if single_link and info.st_nlink != 1:
            raise ValueError("hard-linked files are not allowed")
        handle = os.fdopen(descriptor, "rb")
        descriptor = None  # The file object owns this descriptor from here onward.
        with handle:
            yield handle
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)
