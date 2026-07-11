#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import stat
import tarfile
import zipfile
from pathlib import Path


PART_PATTERN = re.compile(
    r"^(?P<base>.+\.tar)\.(?P<number>[0-9]{3})$",
    re.IGNORECASE,
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)

    return digest.hexdigest()


def discover_split_sets(
    source: Path,
) -> dict[str, list[tuple[int, Path]]]:
    groups: dict[str, list[tuple[int, Path]]] = {}

    for path in source.rglob("*"):
        if not path.is_file():
            continue

        match = PART_PATTERN.match(path.name)

        if match is None:
            continue

        base_name = match.group("base")
        part_number = int(match.group("number"))
        key = str(path.parent.resolve() / base_name)

        groups.setdefault(key, []).append(
            (part_number, path)
        )

    for parts in groups.values():
        parts.sort(key=lambda item: item[0])

    return groups


def validate_split_parts(
    base: str,
    parts: list[tuple[int, Path]],
) -> None:
    actual_numbers = [number for number, _ in parts]

    if not actual_numbers:
        raise RuntimeError(f"{base}: no split parts")

    if actual_numbers[0] != 1:
        raise RuntimeError(
            f"{base}: first part is "
            f"{actual_numbers[0]:03d}; expected 001"
        )

    expected_numbers = list(
        range(1, actual_numbers[-1] + 1)
    )

    if actual_numbers != expected_numbers:
        missing = sorted(
            set(expected_numbers) - set(actual_numbers)
        )

        raise RuntimeError(
            f"{base}: missing parts: "
            + ", ".join(
                f"{number:03d}"
                for number in missing
            )
        )

    if len(parts) > 1:
        regular_sizes = {
            path.stat().st_size
            for _, path in parts[:-1]
        }

        if len(regular_sizes) != 1:
            details = ", ".join(
                f"{path.name}={path.stat().st_size}"
                for _, path in parts[:-1]
            )

            raise RuntimeError(
                f"{base}: inconsistent non-final "
                f"part sizes: {details}"
            )


def concatenate_parts(
    parts: list[tuple[int, Path]],
    output: Path,
) -> None:
    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output.open("wb") as destination:
        for number, path in parts:
            print(
                f"  + part {number:03d}: "
                f"{path.name} "
                f"({path.stat().st_size} bytes)"
            )

            with path.open("rb") as source:
                shutil.copyfileobj(
                    source,
                    destination,
                    length=1024 * 1024,
                )


def ensure_within(
    root: Path,
    candidate: Path,
    description: str,
) -> None:
    root_resolved = root.resolve()
    candidate_resolved = candidate.resolve()

    try:
        candidate_resolved.relative_to(
            root_resolved
        )
    except ValueError as exc:
        raise RuntimeError(
            f"Unsafe {description}: "
            f"{candidate}"
        ) from exc


def safe_tar_extract(
    archive: Path,
    destination: Path,
) -> None:
    destination.mkdir(
        parents=True,
        exist_ok=True,
    )

    with tarfile.open(archive, "r:*") as tar:
        for member in tar.getmembers():
            target = destination / member.name

            ensure_within(
                destination,
                target,
                f"tar path {member.name!r}",
            )

            if (
                member.issym()
                or member.islnk()
                or member.ischr()
                or member.isblk()
                or member.isfifo()
            ):
                raise RuntimeError(
                    "Refusing special tar member: "
                    f"{member.name}"
                )

        try:
            tar.extractall(
                destination,
                filter="data",
            )
        except TypeError:
            tar.extractall(destination)


def zip_member_is_symlink(
    member: zipfile.ZipInfo,
) -> bool:
    mode = member.external_attr >> 16
    return stat.S_ISLNK(mode)


def safe_zip_extract(
    archive: Path,
    destination: Path,
) -> None:
    destination.mkdir(
        parents=True,
        exist_ok=True,
    )

    with zipfile.ZipFile(archive) as zipped:
        for member in zipped.infolist():
            target = (
                destination / member.filename
            )

            ensure_within(
                destination,
                target,
                f"ZIP path {member.filename!r}",
            )

            if zip_member_is_symlink(member):
                raise RuntimeError(
                    "Refusing ZIP symbolic link: "
                    f"{member.filename}"
                )

        zipped.extractall(destination)


def directory_counts(
    root: Path,
) -> tuple[int, int]:
    directories = sum(
        1
        for path in root.rglob("*")
        if path.is_dir()
    )

    files = sum(
        1
        for path in root.rglob("*")
        if path.is_file()
    )

    return directories, files


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--source",
        type=Path,
        default=Path(
            "vendor/ATC_RF03_Ring/SDKs"
        ),
    )

    parser.add_argument(
        "--work",
        type=Path,
        default=Path(
            "reference/bluex-sdk3-v3.3.6"
        ),
    )

    args = parser.parse_args()

    source = args.source.resolve()
    work = args.work.resolve()

    if not source.is_dir():
        raise SystemExit(
            "SDK source directory does not exist: "
            f"{source}"
        )

    split_sets = discover_split_sets(source)

    matching_sets = {
        base: parts
        for base, parts in split_sets.items()
        if "sdk3-release-v3.3.6"
        in Path(base).name.lower()
    }

    if not matching_sets:
        raise SystemExit(
            "No SDK3 v3.3.6 numbered multipart "
            f"archive found below {source}"
        )

    if len(matching_sets) != 1:
        listing = "\n".join(
            f"  {base}: {len(parts)} pieces"
            for base, parts
            in sorted(matching_sets.items())
        )

        raise SystemExit(
            "Multiple matching multipart archives "
            f"were found:\n{listing}"
        )

    source_base, parts = next(
        iter(matching_sets.items())
    )

    validate_split_parts(
        source_base,
        parts,
    )

    archive_dir = work / "archive"
    staging_dir = work / "staging"
    extract_dir = work / "extracted"

    if work.exists() and any(work.iterdir()):
        raise SystemExit(
            f"Work directory is not empty: {work}\n"
            "Remove it before repeating extraction."
        )

    archive_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    outer_archive = (
        archive_dir / Path(source_base).name
    )

    print("Multipart SDK archive discovered:")
    print(f"  Source base: {source_base}")
    print(f"  Part count:  {len(parts)}")
    print(
        f"  Part range:  "
        f"{parts[0][0]:03d}–"
        f"{parts[-1][0]:03d}"
    )
    print(
        f"Combining archive into: "
        f"{outer_archive}"
    )

    concatenate_parts(
        parts,
        outer_archive,
    )

    print(
        f"Combined bytes:  "
        f"{outer_archive.stat().st_size}"
    )
    print(
        f"Combined SHA256: "
        f"{sha256(outer_archive)}"
    )

    if not tarfile.is_tarfile(
        outer_archive
    ):
        prefix = (
            outer_archive
            .read_bytes()[:64]
            .hex()
        )

        raise SystemExit(
            "Combined file is not a tar archive.\n"
            f"First 64 bytes: {prefix}"
        )

    print("Combined archive format: tar")

    safe_tar_extract(
        outer_archive,
        staging_dir,
    )

    staged_files = sorted(
        path
        for path in staging_dir.rglob("*")
        if path.is_file()
    )

    staged_dirs = sorted(
        path
        for path in staging_dir.rglob("*")
        if path.is_dir()
    )

    print(
        f"Outer tar directories: "
        f"{len(staged_dirs)}"
    )
    print(
        f"Outer tar files:       "
        f"{len(staged_files)}"
    )

    if (
        len(staged_files) == 1
        and zipfile.is_zipfile(
            staged_files[0]
        )
    ):
        nested_source = staged_files[0]
        nested_archive = (
            archive_dir / nested_source.name
        )

        shutil.copy2(
            nested_source,
            nested_archive,
        )

        print(
            "Nested archive detected: "
            f"{nested_source.name}"
        )
        print(
            f"Nested ZIP bytes:  "
            f"{nested_archive.stat().st_size}"
        )
        print(
            f"Nested ZIP SHA256: "
            f"{sha256(nested_archive)}"
        )

        safe_zip_extract(
            nested_archive,
            extract_dir,
        )
    elif staged_files:
        print(
            "Outer tar contains the SDK tree "
            "directly."
        )

        staging_dir.rename(extract_dir)
        staging_dir = None
    else:
        raise SystemExit(
            "Outer tar produced no files."
        )

    if (
        staging_dir is not None
        and staging_dir.exists()
    ):
        shutil.rmtree(staging_dir)

    directory_count, file_count = (
        directory_counts(extract_dir)
    )

    print(
        f"Extracted directory: "
        f"{extract_dir}"
    )
    print(
        f"Extracted directories: "
        f"{directory_count}"
    )
    print(
        f"Extracted files:       "
        f"{file_count}"
    )

    if file_count == 0:
        raise SystemExit(
            "Nested extraction produced no files."
        )

    print("Top-level extracted entries:")

    for path in sorted(
        extract_dir.iterdir(),
        key=lambda item: item.name.lower(),
    ):
        kind = (
            "dir "
            if path.is_dir()
            else "file"
        )

        print(f"  {kind}  {path.name}")


if __name__ == "__main__":
    main()
