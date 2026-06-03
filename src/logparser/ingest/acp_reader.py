"""Apple .acp / bb-trace / sysdiagnose support.

Apple iOS devices create baseband logs as:
- Individual .acp files in a bb-trace directory
- MergedFile_Diag.hdf (QUTS format) = merged output from .acp files

.acp File Format (reverse-engineered):
- Sync marker: 0xFFFF A55A (4 bytes)
- Variable-size frames: header(20 bytes) + payload + CRC(4 bytes)
- Frame header: sync(4) + seq(2) + type(2) + payload_len(4) + timestamp(8)
- Frame types: 1 = large container (encrypted/compressed), 4 = data frames
- Payload contains Apple-specific log codes (NOT standard Qualcomm DIAG)
- Data is encrypted/obfuscated — cannot be parsed without Apple's tools

⚠️ Raw .acp parsing is NOT possible without Apple's decryption layer.
   The MergedFile_Diag.hdf is the only accessible format for baseband logs.
   Apple's sysdiagnose tool generates the merged .hdf from .acp files.

Strategy:
1. If user opens a bb-trace directory → look for sibling MergedFile_Diag.hdf
2. If user opens a .acp file → look for MergedFile in same/parent directory
3. If no merged file found → scan for .hdf files nearby
"""

from __future__ import annotations

from pathlib import Path


def is_acp_file(filepath: Path) -> bool:
    """Check if path is an .acp file or a bb-trace directory."""
    if filepath.is_dir() and "bb-trace" in filepath.name:
        return True
    if filepath.suffix.lower() == ".acp":
        return True
    return False


def find_hdf_for_acp(filepath: Path) -> Path | None:
    """Find the MergedFile_Diag.hdf associated with .acp files.

    Searches in:
    1. Same directory as the .acp / bb-trace
    2. Parent directory
    3. Sibling directories (same log session)
    """
    # Determine the base log directory
    if filepath.is_dir():
        base_dir = filepath
    else:
        base_dir = filepath.parent

    # The bb-trace dir is typically alongside other dirs from same capture
    # e.g., log-bb-2025-...-bb-trace/ is next to log-bb-2025-...-MergedFile_Diag.hdf
    search_dirs = [
        base_dir,
        base_dir.parent,
        base_dir.parent.parent,
    ]

    # Also check siblings with similar name prefix
    if "bb-trace" in base_dir.name:
        # log-bb-2025-...-bb-trace → look for log-bb-2025-...*MergedFile*
        prefix = base_dir.name.replace("-bb-trace", "")
        for sibling in base_dir.parent.iterdir():
            if prefix in sibling.name and "Merged" in sibling.name:
                if sibling.suffix.lower() in (".hdf", ".bz2"):
                    return sibling

    # Search in directories
    for search_dir in search_dirs:
        if not search_dir.is_dir():
            continue

        # Look for MergedFile_Diag.hdf
        for f in search_dir.iterdir():
            if "MergedFile" in f.name and f.suffix.lower() == ".hdf":
                return f
            if "MergedFile" in f.name and f.name.endswith(".hdf.bz2"):
                return f

        # Look for any .hdf file
        for f in search_dir.iterdir():
            if f.suffix.lower() == ".hdf" and f.stat().st_size > 100000:
                # Verify it's QUTS format
                with open(f, "rb") as fh:
                    if fh.read(4) == b".hdf":
                        return f

        # Search one level deeper
        for subdir in search_dir.iterdir():
            if subdir.is_dir():
                for f in subdir.iterdir():
                    if "MergedFile" in f.name and f.suffix.lower() == ".hdf":
                        return f

    return None
