"""Генерирует gui/HapasVault/Themes/Icons.xaml из SVG Material Symbols Rounded.

    python gen_icons.py <каталог package/rounded из @material-symbols/svg-500> <выход.xaml>

Геометрии в системе координат viewBox 0 -960 960 960 (их рисует controls:Icon).
"""
import re
import sys
from pathlib import Path

ICONS = """
lock lock-fill lock_open lock_open-fill key key-fill search add delete content_copy
visibility visibility_off settings settings-fill history history-fill shield_lock
shield_lock-fill usb link check check_circle close error warning refresh download
upload dark_mode light_mode contrast palette folder person password casino edit
arrow_back arrow_forward remove crop_square filter_none info logout fingerprint
encrypted tune devices sync lock_reset restart_alt cable key_vertical shield
done_all category account_circle save upload_file keyboard grid_view key_vertical-fill
""".split()

TOKEN = re.compile(r"[A-Za-z]|[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?")


def normalize(d: str) -> str:
    if re.search(r"[aA]", d):
        raise ValueError("arc commands need flag-aware parsing")
    return "F1 " + " ".join(TOKEN.findall(d))


def key(name: str) -> str:
    return "Icon." + "".join(p.capitalize() for p in re.split(r"[_-]", name))


def main(src: str, out: str) -> None:
    rows = []
    for name in ICONS:
        svg = (Path(src) / f"{name}.svg").read_text()
        paths = re.findall(r'<path d="([^"]+)"', svg)
        rows.append(f'    <Geometry x:Key="{key(name)}">{" ".join(normalize(p) for p in paths)}</Geometry>')
    Path(out).write_text(
        "<!-- Сгенерировано gui/tools/gen_icons.py из Material Symbols Rounded (Apache-2.0). -->\n"
        '<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"\n'
        '                    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">\n'
        + "\n".join(rows) + "\n</ResourceDictionary>\n", encoding="utf-8")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
