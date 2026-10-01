"""Create a source archive without scan history, reports, virtualenvs or caches."""
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

root = Path(__file__).resolve().parent.parent
archive = root / "osint_checker-source.zip"
files = [root / name for name in ("README.md", "pyproject.toml", "requirements.txt", "start.ps1", ".gitignore")]
for directory in ("cybercheck", "tests", "scripts", ".github"):
    files.extend(path for path in (root / directory).rglob("*")
                 if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc")
with ZipFile(archive, "w", ZIP_DEFLATED) as output:
    for path in sorted(files):
        output.write(path, path.relative_to(root).as_posix())
print(f"{archive} ({len(files)} files, {archive.stat().st_size:,} bytes)")
