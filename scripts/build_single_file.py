"""Build a compressed single-file bundle of j100-client.

The bundle concatenates every runtime module of the package in dependency
order into one flat source file, strips intra-package imports, compresses
the result with zlib, and wraps it in a small base64 launcher script.

The target platform is an appliance venv (Python 3.9 or higher) that already
provides the required libraries; those dependencies stay imported, not bundled.
The original package files are never modified.

Usage:

    uv run python scripts/build_single_file.py [options]
"""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import shutil
import subprocess
import sys
import time
import zlib
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DIR = REPO_ROOT / "j100_client"

MODULE_ORDER = [
    "bundle_validity",
    "exceptions",
    "models",
    "transport",
    "client",
    "cli",
]

EXCLUDED_MODULES = {"__init__", "__main__"}

BUNDLE_NAME = "j100-client.py"
FLAT_NAME = "j100-client.flat.py"


class BuildError(Exception):
    """A bundle build or verification step failed."""


def module_path(name: str) -> Path:
    return PACKAGE_DIR / f"{name}.py"


def load_module_source(name: str) -> str:
    path = module_path(name)
    if not path.is_file():
        raise BuildError(f"missing module file: {path}")
    return path.read_text(encoding="utf-8")


def parse_module(name: str) -> ast.Module:
    source = load_module_source(name)
    try:
        return ast.parse(source)
    except SyntaxError as error:
        raise BuildError(
            f"cannot parse {module_path(name)}: {error}"
        ) from error


def check_order_covers_package() -> None:
    actual = {
        path.stem
        for path in PACKAGE_DIR.glob("*.py")
        if path.stem not in EXCLUDED_MODULES
    }
    listed = set(MODULE_ORDER)
    missing = sorted(actual - listed)
    extra = sorted(listed - actual)
    if missing or extra:
        details = []
        if missing:
            details.append(f"not listed: {missing}")
        if extra:
            details.append(f"listed but absent: {extra}")
        raise BuildError(
            "MODULE_ORDER does not match the package modules ("
            + "; ".join(details)
            + ")"
        )


def relative_import_targets(tree: ast.Module) -> List[str]:
    targets: List[str] = []
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom) or node.level == 0:
            continue
        if node.module is None:
            targets.extend(
                alias.name.split(".")[0]
                for alias in node.names
                if alias.name != "__version__"
            )
        else:
            targets.append(node.module.split(".")[0])
    return targets


def check_dependency_order() -> None:
    position = {name: index for index, name in enumerate(MODULE_ORDER)}
    for name in MODULE_ORDER:
        tree = parse_module(name)
        for target in relative_import_targets(tree):
            if target not in position:
                raise BuildError(
                    f"j100_client.{name} imports unknown module '{target}'"
                )
            if position[target] >= position[name]:
                raise BuildError(
                    f"j100_client.{name} imports j100_client.{target}, "
                    "which is not earlier in MODULE_ORDER"
                )


def top_level_definitions(tree: ast.Module) -> Dict[str, ast.AST]:
    definitions: Dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            definitions[node.name] = node
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    definitions[target.id] = node
        elif isinstance(node, ast.AnnAssign) and isinstance(
            node.target, ast.Name
        ):
            definitions[node.target.id] = node
    return definitions


def check_name_collisions() -> None:
    definitions: Dict[str, List[tuple[str, ast.AST]]] = {}
    for name in MODULE_ORDER:
        for symbol, node in top_level_definitions(parse_module(name)).items():
            definitions.setdefault(symbol, []).append((name, node))
    for symbol, locations in definitions.items():
        if len(locations) < 2:
            continue
        first = ast.dump(locations[0][1])
        for module, node in locations[1:]:
            if ast.dump(node) != first:
                raise BuildError(
                    f"top-level name '{symbol}' is defined differently in "
                    f"j100_client.{locations[0][0]} and j100_client.{module}"
                )


def _is_intra_package_import(node: ast.AST) -> bool:
    if not isinstance(node, ast.ImportFrom):
        return False
    if node.level > 0 or node.module == "__future__":
        return True
    return (
        node.module is not None
        and node.module.split(".")[0] == PACKAGE_DIR.name
    )


def _is_main_guard(node: ast.AST) -> bool:
    if not isinstance(node, ast.If):
        return False
    test = node.test
    return (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Eq)
        and isinstance(test.left, ast.Name)
        and test.left.id == "__name__"
        and len(test.comparators) == 1
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value == "__main__"
    )


def strip_relative_imports(name: str) -> str:
    source = load_module_source(name)
    tree = ast.parse(source)
    spans = [
        (
            node.lineno,
            node.end_lineno if node.end_lineno is not None else node.lineno,
        )
        for node in tree.body
        if _is_intra_package_import(node) or _is_main_guard(node)
    ]
    drop = {
        line_number
        for start, end in spans
        for line_number in range(start, end + 1)
    }
    kept = [
        line
        for number, line in enumerate(source.splitlines(), start=1)
        if number not in drop
    ]
    return normalize_blank_lines(kept)


def normalize_blank_lines(lines: List[str]) -> str:
    normalized: List[str] = []
    blanks = 0
    for line in lines:
        blanks = blanks + 1 if not line.strip() else 0
        if blanks <= 2:
            normalized.append(line)
    text = "\n".join(normalized).strip("\n")
    return text + "\n" if text else ""


def read_version() -> str:
    for line in load_module_source("__init__").splitlines():
        if line.startswith("__version__"):
            return line.split("=", 1)[1].strip().strip('"')
    raise BuildError("could not read __version__ from __init__.py")


def assemble_flat_source(validity: Optional[float] = None) -> str:
    header = [
        '"""j100-client single-file flat source (generated).',
        "",
        "Concatenation of the j100_client package in dependency order.",
        "Regenerate with scripts/build_single_file.py --keep-flat.",
        '"""',
        "from __future__ import annotations",
        f'__version__ = "{read_version()}"',
    ]
    if validity is not None:
        header.append(f"VALIDITY = {validity!r}")
    chunks: List[str] = ["\n".join(header)]
    for name in MODULE_ORDER:
        banner = "\n".join(
            [
                "# " + "-" * 66,
                f"# j100_client.{name}",
                "# " + "-" * 66,
            ]
        )
        chunks.append(banner + "\n" + strip_relative_imports(name).rstrip("\n"))
        if name == "bundle_validity" and validity is not None:
            chunks.append("_enforce_bundle_validity(VALIDITY)")
    chunks.append('if __name__ == "__main__":\n    main()')
    return "\n\n\n".join(chunks) + "\n"


def wrap_launcher(
    flat_source: str,
    shebang: Optional[str],
    validity: Optional[float] = None,
) -> str:
    blob = base64.encodebytes(zlib.compress(flat_source.encode("utf-8"), 9))
    blob_lines = blob.decode("ascii").splitlines()
    lines: List[str] = []
    if shebang:
        lines.append(f"#!{shebang}")
    if validity is not None:
        lines.append(f"# VALIDITY: {validity!r}")
    payload_description = (
        "The flat j100-client source is zlib-compressed and base64-encoded\n"
        "below. Regenerate with scripts/build_single_file.py.\n\n"
    )
    author_description = (
        "Author: Sabi Szokoly\nContact: https://github.com/sszokoly\n"
    )
    lines.extend(
        [
            '"""j100-client single-file bundle (generated; do not edit).',
            "",
            *payload_description.splitlines(),
            *author_description.splitlines(),
            '"""',
            "import base64",
        ]
    )
    lines.extend(["import sys", "import traceback", "import zlib", "", ""])
    lines.append('COMPRESSED_SCRIPT = """\\')
    lines.extend(blob_lines)
    lines.extend(
        [
            '"""',
            "",
            "",
            "def unwrap_and_decompress(wrapped_text):",
            '    """Unwraps, base64 decodes and decompresses string."""',
            '    base64_str = wrapped_text.replace("\\n", "")',
            "    compressed_bytes = base64.b64decode(base64_str)",
            "    original_string = zlib.decompress(compressed_bytes)",
            '    return original_string.decode("utf-8")',
        ]
    )
    lines.extend(["", "", 'if __name__ == "__main__":'])
    lines.append("    wrapped_script = COMPRESSED_SCRIPT")
    lines.append("    script_content = unwrap_and_decompress(wrapped_script)")
    lines.extend(
        [
            "    try:",
            '        code = compile(script_content, "<j100-client>", "exec")',
            "        exec(code)",
            "    except SystemExit:",
            "        raise",
            "    except KeyboardInterrupt:",
            "        raise",
            "    except Exception:",
            "        traceback.print_exc()",
            "        raise SystemExit(1)",
        ]
    )
    return "\n".join(lines) + "\n"


def run_command(
    command: List[str], label: str, input_text: Optional[str] = None
) -> None:
    result = subprocess.run(
        command,
        cwd=REPO_ROOT,
        check=False,
        input=input_text.encode("utf-8") if input_text is not None else None,
        capture_output=True,
        start_new_session=input_text is not None,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr.decode(errors="replace"))
        raise BuildError(f"{label} failed with exit code {result.returncode}")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def emit_readme(output_dir: Path, shebang: Optional[str]) -> None:
    python = shebang or "python3"
    readme = (
        "# j100-client single-file bundle\n"
        "\n"
        "Generated by `scripts/build_single_file.py`. The bundle embeds the full\n"
        "j100_client package (CLI + API) in one file; run it with venv Python\n"
        "\n"
        "\n"
        "## Check status of J1xx phones\n"
        "\n"
        "```console\n"
        f"{python} j100-client.py status \\\n"
        "  --insecure \\\n"
        "  --password mypass \\\n"
        "  10.10.10.1 10.10.10.2 \\\n"
        "```\n"
        "\n"
        "## Restart a J1xx phone\n"
        "\n"
        "```console\n"
        f"{python} j100-client.py restart \\\n"
        "  --insecure \\\n"
        "  --password mypass \\\n"
        "  10.10.10.1\\\n"
        "```\n"
        "\n"
        "## Disclaimer\n"
        "\n"
        "`j100-client` is an independent tool and is not affiliated with,\n"
        'developed by, endorsed by, or supported by any vendor. It is provided "as\n'
        'is," without warranties of any kind, expressed or implied. Users are\n'
        "responsible for evaluating its suitability and assume all risks associated\n"
        "with its use.\n"
    )
    readme_path = output_dir / "README.md"
    readme_path.write_text(readme, encoding="utf-8")
    print(f"wrote {readme_path}")


def build(
    output_dir: Path,
    keep_flat: bool,
    shebang: Optional[str],
    with_readme: bool,
    validity: Optional[float] = None,
) -> Path:
    print("checking module order and collisions")
    check_order_covers_package()
    check_dependency_order()
    check_name_collisions()

    print("assembling flat source")
    flat_source = assemble_flat_source(validity)
    compile(flat_source, "<flat-bundle>", "exec")

    output_dir.mkdir(parents=True, exist_ok=True)
    if keep_flat:
        flat_path = output_dir / FLAT_NAME
        flat_path.write_text(flat_source, encoding="utf-8")
        print(f"wrote {flat_path}")

    launcher = wrap_launcher(flat_source, shebang, validity)
    compile(launcher, "<launcher>", "exec")
    bundle_path = output_dir / BUNDLE_NAME
    bundle_path.write_text(launcher, encoding="utf-8")
    print(f"wrote {bundle_path}")
    if with_readme:
        emit_readme(output_dir, shebang)
    return bundle_path


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "dist",
        help="directory for generated artifacts (default: dist)",
    )
    parser.add_argument(
        "--keep-flat",
        action="store_true",
        help="also write the readable uncompressed flat source",
    )
    parser.add_argument(
        "--with-readme",
        action="store_true",
        help="also write README.md deployment notes",
    )
    parser.add_argument(
        "--shebang",
        default=None,
        help="optional shebang line emitted as the bundle's first line",
    )
    parser.add_argument(
        "--valid-days",
        type=positive_int,
        default=None,
        help="positive number of days before the generated script expires",
    )
    arguments = parser.parse_args(argv)

    try:
        validity = (
            time.time() + arguments.valid_days * 86400
            if arguments.valid_days is not None
            else None
        )
        bundle_path = build(
            arguments.output_dir,
            arguments.keep_flat,
            arguments.shebang,
            arguments.with_readme,
            validity,
        )

        rebuild = build(
            arguments.output_dir / ".determinism",
            False,
            arguments.shebang,
            False,
            validity,
        )
        rebuild.unlink()
        shutil.rmtree(rebuild.parent)

        kib = bundle_path.stat().st_size / 1024.0
        print(f"done: {bundle_path} ({kib:.1f} KiB)")
        return 0
    except BuildError as error:
        print(f"build failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
