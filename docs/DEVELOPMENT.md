# Разработка

Сборка, тесты, устройство репозитория и выпуск релизов. Как пользоваться
программой — в [README](../README.md), как всё устроено внутри — в
[HOW-IT-WORKS.md](HOW-IT-WORKS.md).

## Что где лежит

```
core/        ядро токена — один и тот же код в прошивке, симуляторе и тестах
  hal.h        функции железа: flash, RNG, время, светодиод, буфер хранилища
  token.c      команды, состояние, лимиты, журнал
  store.c      flash: конфигурация и хранилище, A/B-копии
  session.c    зашифрованный канал (рукопожатие KK + XChaCha20-Poly1305)
  kdf.c        вывод ключей
  bip39.c      24 слова восстановления
  sha.c, otp.c SHA-1/SHA-256/HMAC, TOTP и Steam Guard
  framer.c     сборка кадров из потока байт (USB CDC)
  proto.h      протокол: кадры, команды, статусы, USB VID/PID
firmware/    прошивка для RP2040/RP2350
  main.c            главный цикл: USB CDC <-> token_handle, сброс DTR = блокировка
  hal_rp2040.c      flash, буфер хранилища, RNG, светодиод (GPIO или WS2812 через PIO)
  usb_descriptors.c USB CDC, серийный номер = уникальный ID платы
  emu/              запуск прошивки в эмуляторе RP2040 (rp2040js) для CI
sim/         виртуальный токен: TCP 127.0.0.1:47123 или --pty, flash = файл
client/      библиотека ПК (pmclient), транспорты TCP и USB CDC; pmapi — DLL для программы
tools/       pmcli — консольный клиент; pmhwtest — проверка платы
tests/       автотесты ядра и клиента, фаззер pmfuzz
gui/
  HapasVault.Core/        C#-обёртка над pmapi: TokenClient, ошибки, генератор паролей, Steam
  HapasVault.Core.Tests/  интеграционные тесты против pmtoken_sim
  HapasVault/             WPF-приложение (Material 3 Expressive)
    Theming/   динамический цвет M3: тональные палитры, светлая/тёмная тема, акцент Windows
    Motion/    пружинные и emphasized-кривые
    Controls/  формы с морфингом, индикатор загрузки, волнистый прогресс, радиальное меню
    Themes/    стили контролов, типографика (Roboto), иконки (Material Symbols)
    Views/     экраны и диалоги
    ViewModels/ логика экранов (CommunityToolkit.Mvvm)
    Platform/  трей, иконка, автоввод, автозапуск, Win32
third_party/ Monocypher 4 (X25519, XChaCha20-Poly1305, BLAKE2b, Argon2id)
```

## Ядро, библиотека и утилиты

Нужны CMake и компилятор C11.

**Linux:**
```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
ctest --test-dir build --output-on-failure
```

**Симулятор в pmapi.** Опция `PM_SIMULATOR` (по умолчанию `ON`) включает в
`pmapi` транспорт симулятора — подключение к тестовому токену на 127.0.0.1.
Он нужен тестам C и C# и есть в локальных и предрелизных (`dev`) сборках.
Стабильные выпуски собираются с `-DPM_SIMULATOR=OFF`: `pmapi_attach` сразу
возвращает «нет устройства» и не открывает сокет, `pmapi_has_simulator()`
возвращает 0, программа показывает только USB. Проверка такой сборки:
```
cmake -S . -B build-nosim -DPM_SIMULATOR=OFF && cmake --build build-nosim -j --target pmapi pmnosim
ctest --test-dir build-nosim -R pmnosim --output-on-failure
```

**Visual Studio 2022+** (Developer PowerShell):
```
cmake -S . -B build
cmake --build build --config Release
build\Release\pmtests.exe
```

**MSYS2 / MinGW-w64:**
```
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build
build\pmtests.exe
```

## Программа для Windows

Нужны .NET 8 SDK и собранное ядро в `build/`:
```
cmake -S . -B build -A x64 && cmake --build build --config Release
dotnet test gui/HapasVault.Core.Tests -c Release
dotnet publish gui/HapasVault/HapasVault.csproj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -o publish
```

Ключи запуска: `--demo` (без токена, мастер-пароль `demo`), `--tray` (сразу в
трей), `--screenshots <каталог>` (отрисовать все экраны в PNG и выйти — так их
снимает CI).

## Прошивка

Нужны `gcc-arm-none-eabi` и pico-sdk 2.1.1:
```
cmake -S firmware -B build-fw -DPICO_SDK_PATH=~/pico-sdk -DPICO_BOARD=pico   # или pico2, waveshare_rp2040_zero, pmtoken_rp2040_generic
cmake --build build-fw          # -> build-fw/pmtoken.uf2
```

Если на клоне RP2040-Zero красный и зелёный перепутаны (у части диодов порядок
RGB, а не GRB), добавьте `PMTOKEN_WS2812_RGB=1` в `target_compile_definitions`.

`pmtoken_rp2040_generic` (`firmware/boards/`) — для клонов, на которых не
стартует прошивка для Pico. Флеш читается через `boot2_generic_03h` (команда 0x03
без Quad-режима, clk_sys/4): `boot2_w25q080` из Pico включает Quad командами
Winbond, и с флеш другой серии процессор зависает сразу после загрузчика. Кварц
ждём 64 мс вместо 6. Светодиод — обычный на GP25 и WS2812 на GP16 одновременно.
Другую ножку можно задать при сборке: `-DPMTOKEN_LED_PIN=17` (обычный
светодиод) или `-DPMTOKEN_WS2812_PIN=12` (WS2812). Через `CMAKE_C_FLAGS` этого не
делайте: он затирает флаги процессора из SDK (`-mcpu=cortex-m0plus -mthumb`).

**Диагностика платы** (`firmware/diag/`, цель `pmdiag`, собирается для любой
платы на RP2040 → `build-fw/pmdiag.uf2`). Это no_flash UF2: загрузчик ROM
кладёт его в RAM и запускает с начала RAM, флеш он не стирает. Отчёт выводится
файлом `REPORT.TXT` на USB-диске `PMDIAG` (MSC, FAT12 собирается на лету) и
тем же текстом в COM-порт (CDC). В отчёте:
* ревизия чипа и загрузчика, частоты (счётчик FC0), настройки XOSC;
* флеш: JEDEC ID, регистры состояния, SFDP с QER (как включается Quad);
  0x35 у Macronix/ISSI не отправляется, потому что у них она включает QPI;
* что записано: CRC boot2, есть ли строка `pmtoken`, CRC по 4 КБ первых 128 КБ
  (сверяется с .uf2);
* чтение 0x03 через XIP на clk_sys/8, /4, /2 против медленного эталона;
* запись в сектор 0x3F000 (последний в резерве под прошивку, pmtoken его не
  использует) и стирание обратно;
* boot2 из флеш, запущенный так же, как это делает ROM, и чтение через XIP после
  него.

`pmdiag_flash` (`pmdiag-flash-rp2040.uf2`) — тот же код, собранный как обычная
прошивка во флеш вместо pmtoken. Нужен, когда pmtoken из флеш не доходит до USB,
хотя RAM-диагностика работает. Он показывает, стартует ли с платы код из флеш,
и по одному прогоняет шаги запуска pmtoken: АЦП, `pico_rand`,
`flash_safe_execute`, а затем настоящие `board_init()` и `token_init()` из
`hal_rp2040.c` и `core/`. Прямых тестов SSI в нём нет, потому что код сам
исполняется из флеш. Зависший шаг ловит сторожевой таймер (обычная перезагрузка
из флеш), и он попадает в отчёт.

Этапы, на которых флеш может подвесить шину, идут под сторожевым таймером:
`watchdog_reboot(SRAM_BASE, …)` перезапускает диагностику в себя, RAM при этом
не стирается. Номер зависшего этапа сохраняется в scratch-регистрах, при
следующем запуске этап пропускается и отмечается в отчёте. Затем диагностика
по очереди мигает GPIO 16–25, сначала как обычным светодиодом, потом как WS2812:
GPIO = 15 + число вспышек в группе.

**Без платы.** Прошивка запускается в эмуляторе RP2040
([rp2040js](https://github.com/wokwi/rp2040js)): исполняется настоящий ARM-код
вместе с TinyUSB, USB CDC проброшен на TCP-порт, и `pmhwtest` проходит по нему
весь сценарий. `EMU_WS2812=16` декодирует сигнал RGB-светодиода в цвета,
`EMU_LED=25` печатает переключения обычного светодиода.
```
cd firmware/emu && npm ci && node emu.js ../../build-fw/pmtoken.uf2 47300
pmhwtest tcp:47300
```
Через запятую можно передать несколько UF2: блоки с адресами RAM ложатся в RAM,
и тогда запуск идёт с начала RAM, как после no_flash UF2. Так в CI проверяется
`pmdiag` рядом с прошивкой во флеш. Флеш-команды SPI эмулятор не исполняет,
отвечает нулями, поэтому от этого прогона ждём только, что этапы не виснут и
что через XIP найдена прошивка:
```
node emu.js ../../build-fw/pmtoken.uf2,../../build-fw/pmdiag.uf2 47303 &
node diag-report.js 47303
```

## Попробовать без платы и без программы

Окно 1 — виртуальный токен:
```
pmtoken_sim token_flash.bin
```
Окно 2 — консольный клиент:
```
pmcli
> pair        сопряжение
> setup       24 слова, проверка трёх из них, мастер-пароль
> add         добавить запись
> list        список без паролей
> get 1       логин и пароль одной записи
> backup vault.bak
> quit        = «выдернуть токен», хранилище блокируется
```
Повторный запуск `pmcli` сам установит сессию, останется `unlock`.
Восстановление «на новой плате»: остановите симулятор, удалите
`token_flash.bin` и `pmclient.id`, запустите заново, `pair`, затем
`restore vault.bak`.

С программой (только локальная или предрелизная сборка — в стабильных выпусках
симулятора нет): запустите `tools\pmtoken_sim.exe`, затем `HapasVault.exe` и в
настройках выберите подключение «Симулятор» или «Авто» (по умолчанию — только USB).

## CI и релизы

GitHub Actions (`.github/workflows/build.yml`) на каждый push:

* Linux: ядро под AddressSanitizer/UBSan, фаззер, тесты C#-клиента против
  симулятора;
* Windows: MSVC, WPF, те же тесты, скриншоты всех экранов (артефакт
  `screenshots`), архив программы;
* прошивки для Pico, Pico 2, RP2040-Zero и универсальная RP2040, прогон каждой
  на RP2040 в эмуляторе; диагностика `pmdiag-rp2040.uf2` и её запуск из RAM.

Если всё зелёное, CI **сам публикует релиз**:

| Событие | Релиз |
|---|---|
| push в `main` | `v<VERSION>.<номер сборки>`, помечается последним |
| push тега `v1.2.3` | `v1.2.3` |
| push в любую другую ветку | предрелиз `dev` — всегда последняя сборка, перезаписывается |

Стабильные релизы (`main` и теги) собираются с `pmapi.dll` без симулятора
(`-DPM_SIMULATOR=OFF`) и без `pmtoken_sim.exe` и `pmcli.exe` в архиве; тесты
при этом идут со сборкой с симулятором. Предрелиз `dev` включает симулятор.
Действия GitHub закреплены по SHA коммита (обновляет Dependabot), pico-sdk —
по коммиту, который проверяется после клонирования.

Мажорная и минорная версии — в файле `VERSION`. Каждый файл релиза получает
подписанную через Sigstore запись о происхождении (SLSA provenance). Если в
секретах репозитория заданы `SIGN_PFX_BASE64` и `SIGN_PFX_PASSWORD`,
`HapasVault.exe` и `pmapi.dll` подписываются Authenticode — тогда SmartScreen
перестаёт предупреждать.
