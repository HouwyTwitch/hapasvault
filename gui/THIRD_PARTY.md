# Сторонние компоненты HapasVault

| Компонент | Лицензия | Где |
|---|---|---|
| Monocypher 4 | CC0 / BSD-2-Clause | `third_party/monocypher` (в pmapi.dll) |
| Roboto, Roboto Mono (Google Fonts) | SIL Open Font License 1.1 | `gui/HapasVault/Fonts` (встроены в exe) |
| Material Symbols Rounded | Apache License 2.0 | `gui/HapasVault/Themes/Icons.xaml` (контуры иконок, `gui/tools/gen_icons.py`) |
| CommunityToolkit.Mvvm | MIT | NuGet |
| .NET 8 / WPF | MIT | среда выполнения (входит в self-contained сборку) |
| Список слов BIP39 (английский) | MIT | `core/bip39_words.c` |
| Raspberry Pi Pico SDK | BSD-3-Clause | прошивка (`pmtoken-*.uf2`) |
| TinyUSB | MIT | прошивка (`pmtoken-*.uf2`) |
| rp2040js, bootrom RP2040 | MIT, BSD-3-Clause | только проверка прошивки в CI, в релиз не входят |

Сам HapasVault распространяется под GNU GPL версии 3 или новее (`LICENSE`).
Все компоненты выше совместимы с GPL-3.0.
