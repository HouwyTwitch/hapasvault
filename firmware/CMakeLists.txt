# Прошивка pmtoken для Raspberry Pi Pico (RP2040), Pico 2 (RP2350), Waveshare RP2040-Zero
# и прочих плат на RP2040 (универсальная сборка).
#
#   cmake -S firmware -B build-fw -DPICO_SDK_PATH=/path/to/pico-sdk -DPICO_BOARD=pico
#     PICO_BOARD: pico, pico2, waveshare_rp2040_zero или pmtoken_rp2040_generic (boards/)
#   cmake --build build-fw
#   -> build-fw/pmtoken.uf2: зажать BOOTSEL, подключить, скопировать на диск RPI-RP2
cmake_minimum_required(VERSION 3.13)

# свои описания плат (boards/*.h) — до pico_sdk_import: SDK выбирает плату при подключении
list(APPEND PICO_BOARD_HEADER_DIRS ${CMAKE_CURRENT_LIST_DIR}/boards)

include(pico_sdk_import.cmake)
project(pmtoken_fw C CXX ASM)
set(CMAKE_C_STANDARD 11)
pico_sdk_init()

set(ROOT ${CMAKE_CURRENT_LIST_DIR}/..)

add_executable(pmtoken
  main.c hal_rp2040.c usb_descriptors.c
  # то же ядро, что в симуляторе и тестах
  ${ROOT}/core/token.c ${ROOT}/core/store.c ${ROOT}/core/session.c ${ROOT}/core/kdf.c
  ${ROOT}/core/bip39.c ${ROOT}/core/bip39_words.c ${ROOT}/core/sha.c ${ROOT}/core/otp.c
  ${ROOT}/core/framer.c ${ROOT}/third_party/monocypher/monocypher.c)

target_include_directories(pmtoken PRIVATE ${CMAKE_CURRENT_LIST_DIR} ${ROOT}/core ${ROOT}/third_party/monocypher)
target_compile_options(pmtoken PRIVATE -Wall -Wextra -Wno-unused-parameter -O2)
target_compile_definitions(pmtoken PRIVATE
  PICO_STACK_SIZE=0x1000          # весь SCRATCH_Y; Monocypher — около 1,5 КБ (см. README)
  PICO_HEAP_SIZE=0x400            # malloc не используется
  PICO_FLASH_ASSUME_CORE1_SAFE=1) # ядро 1 не запускаем

target_link_libraries(pmtoken PRIVATE
  pico_stdlib pico_unique_id pico_rand pico_flash
  hardware_flash hardware_watchdog hardware_adc
  tinyusb_device)

pico_enable_stdio_usb(pmtoken 0)    # USB занят нашим CDC
pico_enable_stdio_uart(pmtoken 0)
pico_set_program_name(pmtoken "pmtoken")
pico_set_program_description(pmtoken "HapasVault hardware password token")
pico_add_extra_outputs(pmtoken)

# RGB-светодиод WS2812 (RP2040-Zero и подобные) — через PIO; программа уже
# ассемблирована в ws2812_pio.h (pioasm из pico-sdk 2.1.1 не собирается новыми GCC)
target_link_libraries(pmtoken PRIVATE hardware_pio)

# Своя ножка светодиода: cmake ... -DPMTOKEN_LED_PIN=17 и/или -DPMTOKEN_WS2812_PIN=12
# (описания плат задают их через #ifndef, поэтому определение с командной строки главнее)
if (DEFINED PMTOKEN_LED_PIN)
  target_compile_definitions(pmtoken PRIVATE PICO_DEFAULT_LED_PIN=${PMTOKEN_LED_PIN})
endif()
if (DEFINED PMTOKEN_WS2812_PIN)
  target_compile_definitions(pmtoken PRIVATE PICO_DEFAULT_WS2812_PIN=${PMTOKEN_WS2812_PIN})
endif()

# pmdiag — диагностика платы на RP2040, которая работает из RAM (no_flash UF2) и не
# трогает прошивку во флеш: отчёт REPORT.TXT на USB-диске. Собирается для любой
# платы RP2040; в CI — в сборке pmtoken_rp2040_generic (кварц ждём 64 мс).
if (PICO_PLATFORM STREQUAL "rp2040")
  add_executable(pmdiag diag/pmdiag.c diag/diag_usb.c diag/diag_disk.c)
  target_include_directories(pmdiag PRIVATE ${CMAKE_CURRENT_LIST_DIR}/diag)
  target_compile_options(pmdiag PRIVATE -Wall -Wextra -Wno-unused-parameter -O2)
  target_link_libraries(pmdiag PRIVATE
    pico_stdlib pico_unique_id hardware_pio hardware_watchdog tinyusb_device)
  pico_set_binary_type(pmdiag no_flash)
  pico_enable_stdio_usb(pmdiag 0)
  pico_enable_stdio_uart(pmdiag 0)
  pico_set_program_name(pmdiag "pmdiag")
  pico_set_program_description(pmdiag "HapasVault RP2040 board diagnostics (runs from RAM)")
  pico_add_extra_outputs(pmdiag)
endif()
