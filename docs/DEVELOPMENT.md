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
cmake -S firmware -B build-fw -DPICO_SDK_PATH=~/pico-sdk -DPICO_BOARD=pico   # или pico2, waveshare_rp2040_zero
cmake --build build-fw          # -> build-fw/pmtoken.uf2
```

Если на клоне RP2040-Zero красный и зелёный перепутаны (у части диодов порядок
RGB, а не GRB), добавьте `PMTOKEN_WS2812_RGB=1` в `target_compile_definitions`.

**Без платы.** Прошивка запускается в эмуляторе RP2040
([rp2040js](https://github.com/wokwi/rp2040js)): исполняется настоящий ARM-код
вместе с TinyUSB, USB CDC проброшен на TCP-порт, и `pmhwtest` проходит по нему
весь сценарий. `EMU_WS2812=16` декодирует сигнал RGB-светодиода в цвета.
```
cd firmware/emu && npm ci && node emu.js ../../build-fw/pmtoken.uf2 47300
pmhwtest tcp:47300
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

С программой: запустите `tools\pmtoken_sim.exe`, затем `HapasVault.exe` — он
найдёт виртуальный токен (режим подключения «Авто»).

## CI и релизы

GitHub Actions (`.github/workflows/build.yml`) на каждый push:

* Linux: ядро под AddressSanitizer/UBSan, фаззер, тесты C#-клиента против
  симулятора;
* Windows: MSVC, WPF, те же тесты, скриншоты всех экранов (артефакт
  `screenshots`), архив программы;
* прошивки для Pico, Pico 2 и RP2040-Zero, прогон каждой в эмуляторе RP2040.

Если всё зелёное, CI **сам публикует релиз**:

| Событие | Релиз |
|---|---|
| push в `main` | `v<VERSION>.<номер сборки>`, помечается последним |
| push тега `v1.2.3` | `v1.2.3` |
| push в любую другую ветку | предрелиз `dev` — всегда последняя сборка, перезаписывается |

Мажорная и минорная версии — в файле `VERSION`. Каждый файл релиза получает
подписанную через Sigstore запись о происхождении (SLSA provenance). Если в
секретах репозитория заданы `SIGN_PFX_BASE64` и `SIGN_PFX_PASSWORD`,
`HapasVault.exe` и `pmapi.dll` подписываются Authenticode — тогда SmartScreen
перестаёт предупреждать.
