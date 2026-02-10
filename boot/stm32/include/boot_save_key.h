#ifndef _BOOT_SAVE_KEY_H_
#define _BOOT_SAVE_KEY_H_

#include "stm32wlxx_hal.h"

int save_hw_key(int len, unsigned char * private_buf_der);

#endif /*_BOOT_SAVE_KEY_H_*/
