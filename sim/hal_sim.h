/* Дополнительные функции HAL симулятора (для main и тестов). */
#ifndef PM_HAL_SIM_H
#define PM_HAL_SIM_H

#include <stdint.h>

/* Подключить файл-образ flash (NULL = только в памяти). 0 = ок. */
int hal_sim_open(const char *path);

/* Прямой доступ к образу flash (тесты: имитация порчи/выдёргивания). */
uint8_t *hal_sim_flash(void);

/* Стереть весь образ (= новая чистая плата). */
void hal_sim_erase(void);

/* Сдвиг виртуального времени (тесты rate limit и задержек). */
void hal_sim_advance_ms(uint64_t ms);

/* Не печатать смены состояния светодиода. */
void hal_sim_quiet(int quiet);

#endif
