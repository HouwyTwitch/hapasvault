cmake_minimum_required(VERSION 3.13)
project(pmtoken C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
# статические библиотеки входят в pmapi.so/.dll
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(MSVC)
  add_compile_options(/W4 /utf-8)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS _WINSOCK_DEPRECATED_NO_WARNINGS)
else()
  add_compile_options(-Wall -Wextra -O2)
endif()

# Ядро токена — этот же набор файлов войдёт в прошивку RP2040
add_library(pmcore STATIC
  core/token.c core/store.c core/session.c core/kdf.c
  core/bip39.c core/bip39_words.c core/sha.c core/otp.c core/framer.c
  third_party/monocypher/monocypher.c)
target_include_directories(pmcore PUBLIC core third_party/monocypher)

# Клиент ПК (позже — DLL для GUI)
add_library(pmclient STATIC client/pmclient.c client/pmnet.c client/pmserial.c)
target_include_directories(pmclient PUBLIC client)
target_link_libraries(pmclient PUBLIC pmcore)
if(WIN32)
  target_link_libraries(pmclient PUBLIC ws2_32 bcrypt crypt32 setupapi advapi32)
endif()

# Транспорт симулятора в pmapi (тестовый токен на 127.0.0.1). OFF — стабильные выпуски:
# любой локальный процесс мог бы выдать себя за токен на этом порту.
option(PM_SIMULATOR "pmapi умеет подключаться к симулятору (предрелизные и локальные сборки)" ON)

# C ABI для GUI (C# P/Invoke): pmapi.dll / pmapi.so (без "lib" и на MinGW)
add_library(pmapi SHARED client/pmapi.c)
target_link_libraries(pmapi PRIVATE pmclient)
if(NOT PM_SIMULATOR)
  target_compile_definitions(pmapi PRIVATE PM_NO_SIMULATOR)
endif()
set_target_properties(pmapi PROPERTIES C_VISIBILITY_PRESET hidden PREFIX "")
if(UNIX AND NOT APPLE)
  target_link_options(pmapi PRIVATE -Wl,--exclude-libs,ALL)
endif()

# Виртуальный токен
add_executable(pmtoken_sim sim/sim_main.c sim/hal_sim.c)
target_include_directories(pmtoken_sim PRIVATE sim)
target_link_libraries(pmtoken_sim PRIVATE pmcore pmclient)

# Консольный клиент
add_executable(pmcli tools/pmcli.c)
target_link_libraries(pmcli PRIVATE pmclient)

# Проверка настоящего токена (USB) или эмулятора прошивки
add_executable(pmhwtest tools/pmhwtest.c)
target_link_libraries(pmhwtest PRIVATE pmclient)

# Тесты
enable_testing()
add_executable(pmtests tests/test_main.c sim/hal_sim.c)
target_include_directories(pmtests PRIVATE sim)
target_link_libraries(pmtests PRIVATE pmcore pmclient)
add_test(NAME pmtests COMMAND pmtests)

# Фаззинг разбора команд и кадров (в CI — под ASan/UBSan)
add_executable(pmfuzz tests/fuzz_main.c sim/hal_sim.c)
target_include_directories(pmfuzz PRIVATE sim)
target_link_libraries(pmfuzz PRIVATE pmcore pmclient)
add_test(NAME pmfuzz COMMAND pmfuzz 30000)

# Сборка без симулятора: pmapi_attach не открывает сокет даже при слушателе на порту
if(NOT PM_SIMULATOR)
  add_executable(pmnosim tests/nosim_main.c)
  target_link_libraries(pmnosim PRIVATE pmapi pmclient)
  add_test(NAME pmnosim COMMAND pmnosim)
endif()
