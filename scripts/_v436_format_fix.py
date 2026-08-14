from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_exact(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    if new in text and old not in text:
        return
    if text.count(old) != 1:
        raise RuntimeError(f"{path}: expected exactly one formatting anchor")
    target.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")


def main() -> None:
    replace_exact(
        "scripts/_v436_upgrade.py",
        '''    if "_install_provider_contracts" not in text:\n        text = text.rstrip() + install + "\\n"\n    write("toolkit/ztad/providers.py", text)\n''',
        '''    if "_install_provider_contracts" not in text:\n        text = text.rstrip() + install\n    write("toolkit/ztad/providers.py", text.rstrip() + "\\n")\n''',
    )
    replace_exact(
        "scripts/_v436_governance_finalize.py",
        '''        text = text.rstrip() + section + "\\n"\n''',
        '''        text = text.rstrip() + section.rstrip() + "\\n"\n''',
    )
    Path(__file__).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
