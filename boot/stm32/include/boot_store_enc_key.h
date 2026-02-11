#ifndef _BOOT_STORE_ENC_KEY_H_
#define _BOOT_STORE_ENC_KEY_H_

#include "stm32wlxx_hal.h"

int store_enc_key(int len, unsigned char * private_buf_der);

#endif /*_BOOT_STORE_ENC_KEY_H_*/
