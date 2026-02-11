#include "stm32wlxx_hal.h"
#include "bootutil/bootutil_log.h"
#include <string.h>
#ifdef BAREMETAL
#include "key.h"
#endif //BAREMETAL


#define LENGTH_DOUBLE_WORD	(8)
#define MIN_SECTOR_SIZE     (0x800)
#define BASE                (0x08000000)

#ifdef BAREMETAL
// to permit to debug
static uint64_t data_to_write = 0;
#endif //BAREMETAL


int store_enc_key(int len, unsigned char * private_buf_der)
{

#ifdef BAREMETAL
	if (!private_buf_der)
	{
		BOOT_LOG_ERR("private_buf_der NULL");
		return -1;
	}

	// erase
	HAL_FLASH_Unlock();

	uint32_t adress_private_key = (uint32_t) enc_priv_key;

	FLASH_EraseInitTypeDef erase = {
	        .TypeErase = FLASH_TYPEERASE_PAGES,
	        .Page = ((adress_private_key - BASE) / MIN_SECTOR_SIZE),
	        .NbPages = 1,
	    };

    uint32_t page_error;

    if (HAL_FLASHEx_Erase(&erase, &page_error) != HAL_OK)
    {
        HAL_FLASH_Lock();
        BOOT_LOG_ERR("Key generation failed !!!.\nErase issue");
        return -1;
    }
    HAL_FLASH_Lock();

    // flash
    HAL_FLASH_Unlock();

	// be careful LENGTH_PRIVATE_KEY = 138/8 = 7. need to change if LENGTH_PRIVATE_KEY is no more multiple of 8
	for (uint16_t i = 0; i < len; i = i + LENGTH_DOUBLE_WORD)
	{
		memcpy(&data_to_write, &private_buf_der[i], sizeof(uint64_t));

		if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, adress_private_key + i, data_to_write) != HAL_OK)
		{
			BOOT_LOG_ERR("Key generation failed !!!.\nFlash issue");
			HAL_FLASH_Lock();
			return len;
		}
	}

	HAL_FLASH_Lock();

	return 0;
#endif //#ifdef BAREMETAL
}


