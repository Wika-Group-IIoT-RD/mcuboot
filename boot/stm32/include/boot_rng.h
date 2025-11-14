#ifndef _BOOT_RNG_H_
#define _BOOT_RNG_H_

#include "stm32wlxx_hal.h"

extern RNG_HandleTypeDef hrng;

HAL_StatusTypeDef generator_hw_rng(uint32_t* val);

#endif /*_BOOT_RNG_H_*/
