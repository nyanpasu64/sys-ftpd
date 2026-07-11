#!/bin/python3

from pathlib import Path

DIRNAMES = ["00000000", "11111111", "22222222", "33333333"]


def gen(current_dir: Path, file_prefix: str, depth: int):
    if depth >= 4:
        file_name = f"{file_prefix}.txt"
        file_path = current_dir / file_name

        # create empty text file
        with file_path.open("w") as f:
            contents = file_prefix
            f.write(contents)

        return

    else:
        for dir_name in DIRNAMES:
            child_dir = current_dir / dir_name
            child_dir.mkdir(parents=True, exist_ok=True)
            gen(child_dir, file_prefix + dir_name[0], depth + 1)


gen(Path("."), "", 0)
