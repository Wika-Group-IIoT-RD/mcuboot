#ifndef H_BOOTUTIL_HW_SAVE_KEY_H_
#define H_BOOTUTIL_HW_SAVE_KEY_H_

#include "ignore.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <mcuboot_config/mcuboot_config.h>

#if defined(GENERATE_KEY)
#include <mcuboot_config/mcuboot_save_key.h>
#define BOOT_SAVE_KEY(...) MCUBOOT_SAVE_KEY(__VA_ARGS__)
#else
#define BOOT_SAVE_KEY(...) IGNORE(__VA_ARGS__)
#endif /* GENERATE_KEY */

#ifdef __cplusplus
}
#endif

#endif // H_BOOTUTIL_HW_SAVE_KEY_H_
