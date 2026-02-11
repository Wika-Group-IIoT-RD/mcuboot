/*
 * Copyright (c) 2025 WIKA Alexander Wiegand SE & Co. KG
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "boot_store_enc_key.h"
#include <zephyr/storage/flash_map.h>
#include <zephyr/drivers/flash.h>

// key size 138 and double word 8
#define FIXED_KEY_LEN 138
int
store_enc_key(const unsigned char *key, size_t key_len)
{

    const struct flash_area *fa;
    int rc = flash_area_open(FIXED_PARTITION_ID(storage_partition), &fa);
    if (rc)
    {

        return rc;
    }

    const struct device *dev = flash_area_get_device(fa);
    size_t wb = flash_get_write_block_size(dev);

    size_t store_len = FIXED_KEY_LEN;
    size_t len_align = FIXED_KEY_LEN % wb;
    if (len_align !=0)
    {
        store_len += (wb - len_align);
    }

    if (store_len > FIXED_KEY_LEN + 32)
    {
        flash_area_close(fa);
    }

    uint8_t buf_key[FIXED_KEY_LEN + 32];
    memset(buf_key, 0XFF, store_len);
    memcpy(buf_key,key,FIXED_KEY_LEN);

    rc= flash_area_erase(fa, 0, fa->fa_size);
    if (rc)
    {

        flash_area_close(fa);
        return rc;
    }

    rc = flash_area_write(fa,0,buf_key, store_len);
    flash_area_close(fa);
    return rc;


}