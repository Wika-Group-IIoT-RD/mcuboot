#ifndef H_BOOTUTIL_HW_STORE_ENC_KEY_H_
#define H_BOOTUTIL_HW_STORE_ENC_KEY_H_

#include "ignore.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <mcuboot_config/mcuboot_config.h>

#if defined(MCUBOOT_GEN_ENC_KEY)
#include <mcuboot_config/mcuboot_store_enc_key.h>
#define BOOT_STORE_ENC_KEY(...) MCUBOOT_STORE_ENC_KEY(__VA_ARGS__)
#else
#define BOOT_STORE_ENC_KEY(...) IGNORE(__VA_ARGS__)
#endif /* MCUBOOT_GEN_ENC_KEY */

#ifdef __cplusplus
}
#endif

#endif // H_BOOTUTIL_HW_STORE_ENC_KEY_H_
