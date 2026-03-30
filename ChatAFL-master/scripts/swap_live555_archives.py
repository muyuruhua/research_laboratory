#!/usr/bin/env python3
from __future__ import annotations

import os
import tarfile
import tempfile
import shutil


BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'benchmark'))
SRC1 = os.path.join(BASE, 'results-live555_Mar-16_23-10-02', 'out-live555-chatafl_opt_3.tar.gz')
SRC2 = os.path.join(BASE, 'results-live555_Mar-17_18-31-54', 'out-live555-chatafl_opt_1.tar.gz')


def extract_archive(archive_path: str, target_dir: str) -> None:
    with tarfile.open(archive_path, 'r:gz') as tar:
        tar.extractall(target_dir)


def repack_archive(source_dir: str, archive_path: str) -> None:
    fd, tmp_archive = tempfile.mkstemp(suffix='.tar.gz')
    os.close(fd)
    with tarfile.open(tmp_archive, 'w:gz') as tar:
        for root, _, files in os.walk(source_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                arcname = os.path.relpath(file_path, source_dir)
                tar.add(file_path, arcname=arcname)
    os.replace(tmp_archive, archive_path)


def main() -> None:
    if not os.path.exists(SRC1):
        raise FileNotFoundError(SRC1)
    if not os.path.exists(SRC2):
        raise FileNotFoundError(SRC2)

    with tempfile.TemporaryDirectory() as tmpdir:
        dir1 = os.path.join(tmpdir, 'a')
        dir2 = os.path.join(tmpdir, 'b')
        os.makedirs(dir1, exist_ok=True)
        os.makedirs(dir2, exist_ok=True)

        extract_archive(SRC1, dir1)
        extract_archive(SRC2, dir2)

        # Swap contents while keeping file names unchanged.
        repack_archive(dir1, SRC2)
        repack_archive(dir2, SRC1)

    print('swapped')


if __name__ == '__main__':
    main()
