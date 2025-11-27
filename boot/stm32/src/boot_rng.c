#include "stm32wlxx_hal.h"

RNG_HandleTypeDef hhrng;

HAL_StatusTypeDef generator_hw_rng(uint32_t* val){

    return HAL_RNG_GenerateRandomNumber(&hhrng, val);
}
