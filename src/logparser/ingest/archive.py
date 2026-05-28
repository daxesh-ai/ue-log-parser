"""Archive extraction — handles .zip, .tar, .tar.gz, .tar.bz2, .bz2 files.

Extracts archives to a temp directory, finds .hdf files inside, and returns
the path to the first .hdf file found.
"""

from __future__ import annotations

import bz2
import os
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path

# Supported archive extensions
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".bz2", ".tgz"}


def is_archive(filepath: Path) -> bool:
    """Check if a file is a supported archive format.

    Note: sysdiagnose_*.tar.gz is handled by logarchive_reader, not here.
    """
    name = filepath.name.lower()
    # sysdiagnose archives are handled separately
    if name.startswith("sysdiagnose") and name.endswith(".tar.gz"):
        return False
    if name.endswith((".tar.gz", ".tar.bz2")):
        return True
    return filepath.suffix.lower() in ARCHIVE_EXTENSIONS


def extract_hdf_from_archive(filepath: Path) -> Path | None:
    """Extract archive and return path to first .hdf file found.

    Creates a temporary directory for extraction. Caller should clean up
    with cleanup_temp_dir() when done.

    Returns None if no .hdf file found inside.
    """
    temp_dir = tempfile.mkdtemp(prefix="logparser_")

    try:
        name_lower = filepath.name.lower()

        if name_lower.endswith(".zip"):
            _extract_zip(filepath, temp_dir)
        elif name_lower.endswith((".tar.gz", ".tgz")):
            _extract_tar(filepath, temp_dir, mode="r:gz")
        elif name_lower.endswith(".tar.bz2"):
            _extract_tar(filepath, temp_dir, mode="r:bz2")
        elif name_lower.endswith(".tar"):
            _extract_tar(filepath, temp_dir, mode="r:")
        elif name_lower.endswith(".bz2"):
            # Single file bz2 compression
            return _extract_bz2(filepath, temp_dir)
        else:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return None

        # Find .hdf files in extracted content
        hdf_files = _find_hdf_files(Path(temp_dir))

        if hdf_files:
            hdf_files.sort(key=lambda p: p.stat().st_size, reverse=True)
            return hdf_files[0]

        # No .hdf found — check for .pcap files
        pcap_files = _find_files_by_ext(Path(temp_dir), (".pcap", ".pcapng"))
        if pcap_files:
            pcap_files.sort(key=lambda p: p.stat().st_size, reverse=True)
            return pcap_files[0]

        # No .hdf found — look for nested archives (.tar inside .zip, etc.)
        nested = _find_nested_archives(Path(temp_dir))
        for nested_archive in nested:
            try:
                nested_name = nested_archive.name.lower()
                nested_dest = Path(temp_dir) / "nested_extract"
                nested_dest.mkdir(exist_ok=True)

                if nested_name.endswith((".tar.gz", ".tgz")):
                    _extract_tar(nested_archive, str(nested_dest), "r:gz")
                elif nested_name.endswith(".tar.bz2"):
                    _extract_tar(nested_archive, str(nested_dest), "r:bz2")
                elif nested_name.endswith(".tar"):
                    _extract_tar(nested_archive, str(nested_dest), "r:")
                elif nested_name.endswith(".zip"):
                    _extract_zip(nested_archive, str(nested_dest))

                hdf_files = _find_hdf_files(nested_dest)
                if hdf_files:
                    hdf_files.sort(key=lambda p: p.stat().st_size, reverse=True)
                    return hdf_files[0]

                # Also check nested for .pcap
                pcap_files = _find_files_by_ext(nested_dest, (".pcap", ".pcapng"))
                if pcap_files:
                    pcap_files.sort(key=lambda p: p.stat().st_size, reverse=True)
                    return pcap_files[0]
            except Exception:
                continue

        # Check if this is an Apple bb-trace archive (.acp files only)
        acp_files = _find_files_by_ext(Path(temp_dir), (".acp",))
        if not acp_files:
            # Check nested extraction too
            nested_path = Path(temp_dir) / "nested_extract"
            if nested_path.exists():
                acp_files = _find_files_by_ext(nested_path, (".acp",))

        if acp_files:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise ValueError(
                f"This archive contains {len(acp_files)} Apple .acp files but no MergedFile_Diag.hdf.\n\n"
                f"Apple bb-trace .acp files require merging before analysis.\n"
                f"To fix: Open the MergedFile_Diag.hdf that was generated alongside this capture,\n"
                f"or use Apple's baseband tools to merge the .acp files into a single .hdf."
            )

        shutil.rmtree(temp_dir, ignore_errors=True)
        return None

    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def _extract_zip(filepath: Path, dest: str):
    with zipfile.ZipFile(filepath, "r") as zf:
        zf.extractall(dest)


def _extract_tar(filepath: Path, dest: str, mode: str):
    with tarfile.open(filepath, mode) as tf:
        tf.extractall(dest, filter="data")


def _extract_bz2(filepath: Path, dest: str) -> Path | None:
    """Extract a single bz2-compressed file."""
    # Determine output filename (strip .bz2)
    out_name = filepath.stem
    out_path = Path(dest) / out_name

    with bz2.open(filepath, "rb") as f_in:
        with open(out_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

    if out_path.suffix.lower() == ".hdf":
        return out_path

    # Check if extracted file is actually a tar
    if tarfile.is_tarfile(out_path):
        tar_dest = Path(dest) / "extracted"
        tar_dest.mkdir()
        with tarfile.open(out_path, "r:") as tf:
            tf.extractall(tar_dest, filter="data")
        hdf_files = _find_hdf_files(tar_dest)
        if hdf_files:
            hdf_files.sort(key=lambda p: p.stat().st_size, reverse=True)
            return hdf_files[0]

    # Check if it's actually .hdf content regardless of extension
    with open(out_path, "rb") as f:
        magic = f.read(4)
    if magic == b".hdf":
        return out_path

    return None


def _find_nested_archives(root: Path) -> list[Path]:
    """Find archive files inside an extracted directory."""
    archives = []
    for dirpath, dirnames, filenames in os.walk(root):
        for fname in filenames:
            fpath = Path(dirpath) / fname
            name_lower = fname.lower()
            if name_lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".zip")):
                archives.append(fpath)
            elif tarfile.is_tarfile(fpath):
                archives.append(fpath)
    # Sort by size descending (largest likely contains the logs)
    archives.sort(key=lambda p: p.stat().st_size, reverse=True)
    return archives


def _find_files_by_ext(root: Path, extensions: tuple[str, ...]) -> list[Path]:
    """Recursively find files with given extensions."""
    results = []
    for dirpath, dirnames, filenames in os.walk(root):
        for fname in filenames:
            if fname.lower().endswith(extensions):
                results.append(Path(dirpath) / fname)
    return results


def _find_hdf_files(root: Path) -> list[Path]:
    """Recursively find all .hdf files under a directory."""
    hdf_files = []
    for dirpath, dirnames, filenames in os.walk(root):
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fname.lower().endswith(".hdf"):
                hdf_files.append(fpath)
            elif fpath.stat().st_size > 1000:
                # Check magic bytes for .hdf files with wrong extension
                try:
                    with open(fpath, "rb") as f:
                        if f.read(4) == b".hdf":
                            hdf_files.append(fpath)
                except OSError:
                    pass
    return hdf_files
