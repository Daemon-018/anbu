"""Validate an APK archive before parsing it.

The APK is hostile input. Everything here is cheap and runs before androguard.
"""

from __future__ import annotations

import hashlib
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MAX_FILE_SIZE = 512 * 1024 * 1024          # 512 MiB
MAX_TOTAL_UNCOMPRESSED = 2 * 1024 * 1024 * 1024  # 2 GiB
MAX_ENTRIES = 50_000
MAX_ENTRY_SIZE = 512 * 1024 * 1024
MAX_RATIO = 1000                           # compressed -> uncompressed
DEX_RE = re.compile(r"^classes\d*\.dex$")


class IngestError(ValueError):
    """The file is not a safe, parseable APK."""


@dataclass
class IngestResult:
    path: Path
    sha256: str
    size: int
    entries: int
    dex_names: list[str]
    assets: list[str]
    native_libs: list[str]


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _check_name(name: str) -> None:
    if not name or "\x00" in name:
        raise IngestError("archive contains an empty or NUL-bearing entry name")
    if "\\" in name:
        raise IngestError(f"archive contains a Windows path separator: {name!r}")
    pure = PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts:
        raise IngestError(f"archive contains a path traversal entry: {name!r}")


def validate_apk(path: str | Path) -> IngestResult:
    apk_path = Path(path)
    if not apk_path.exists():
        raise IngestError(f"file not found: {apk_path}")
    if not apk_path.is_file():
        raise IngestError(f"not a regular file: {apk_path}")

    size = apk_path.stat().st_size
    if size == 0:
        raise IngestError("file is empty")
    if size > MAX_FILE_SIZE:
        raise IngestError(f"file exceeds {MAX_FILE_SIZE} bytes")

    if not zipfile.is_zipfile(apk_path):
        raise IngestError("file is not a ZIP/APK archive")

    try:
        with zipfile.ZipFile(apk_path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ENTRIES:
                raise IngestError(f"archive has more than {MAX_ENTRIES} entries")

            total = 0
            names: list[str] = []
            for info in infos:
                _check_name(info.filename)
                if info.flag_bits & 0x1:
                    raise IngestError("archive contains an encrypted entry")
                if info.file_size > MAX_ENTRY_SIZE:
                    raise IngestError(f"entry too large: {info.filename}")
                total += info.file_size
                if total > MAX_TOTAL_UNCOMPRESSED:
                    raise IngestError("archive expands beyond the size limit")
                if (
                    info.compress_size > 0
                    and info.file_size > 10 * 1024 * 1024
                    and info.file_size / info.compress_size > MAX_RATIO
                ):
                    raise IngestError(f"entry has a suspicious compression ratio: {info.filename}")
                names.append(info.filename)

            dex_names = [n for n in names if DEX_RE.match(n)]
            if "AndroidManifest.xml" not in names:
                raise IngestError("APK is missing AndroidManifest.xml")
            if not dex_names:
                raise IngestError("APK contains no classes*.dex")

            assets = [n for n in names if n.startswith("assets/") and not n.endswith("/")]
            native_libs = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
    except zipfile.BadZipFile as exc:
        raise IngestError(f"corrupt ZIP archive: {exc}") from exc

    return IngestResult(
        path=apk_path,
        sha256=sha256_file(apk_path),
        size=size,
        entries=len(infos),
        dex_names=dex_names,
        assets=assets,
        native_libs=native_libs,
    )
