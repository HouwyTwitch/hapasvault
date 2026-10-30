# Прошивка pmtoken для Raspberry Pi Pico (RP2040) и Pico 2 (RP2350).
#
#   cmake -S firmware -B build-fw -DPICO_SDK_PATH=/path/to/pico-sdk -DPICO_BOARD=pico   # или pico2
#   cmake --build build-fw
#   -> build-fw/pmtoken.uf2: зажать BOOTSEL, подключить, скопировать на диск RPI-RP2
cmake_minimum_required(VERSION 3.13)

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
