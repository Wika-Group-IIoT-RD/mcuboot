#include "stm32wlxx_hal.h"

RNG_HandleTypeDef hrng;

HAL_StatusTypeDef generator_hw_rng(uint32_t* val){

    return HAL_RNG_GenerateRandomNumber(&hrng, val);
}
