#ifndef MCUBOOT_CONFIG_H
#define MCUBOOT_CONFIG_H

#define MCUBOOT_IMAGE_NUMBER 1
#define IMAGE_EXECUTABLE_RAM_START 0x20000000
#define IMAGE_EXECUTABLE_RAM_SIZE 0x100000

//#define MCUBOOT_OVERWRITE_ONLY 1
#undef MCUBOOT_RAM_LOAD
//#define MCUBOOT_DIRECT_XIP 1
//#define MCUBOOT_DIRECT_XIP_REVERT 1
#define  MCUBOOT_SWAP_USING_MOVE 1
//#define MCUBOOT_MODE_SWAP_USING_SCRATCH 1

#define MCUBOOT_MAX_IMG_SECTORS 128

// simple configuration : tinycrypt with only signature
#if defined(TINYCRYPT)
#define MCUBOOT_USE_TINYCRYPT
#define MCUBOOT_VALIDATE_SLOT0 1
#define MCUBOOT_ENCRYPT_EC256


#elif defined(MBEDTLS)
#define MCUBOOT_USE_MBED_TLS
#define MCUBOOT_VALIDATE_SLOT0 1
// todo : use AES ????
#if defined(AES_256)
#define MCUBOOT_AES_256
#elif defined(AES_128)
#define MCUBOOT_AES_128
#endif //AES_256

#else
#error ""ERROR : CHOOSE between tinycrypt or mbedtls""
#endif //TINYCRYPT

// signature is always ECDSA_P256
#define MCUBOOT_SIGNATURE_TYPE_ECDSA_P256
#define MCUBOOT_SIGN_EC256

#if defined(ACTIVATE_ENCRYPTION)
#define MCUBOOT_ENC_IMAGES
#else
#undef MCUBOOT_ENC_IMAGES
#endif //ACTIVATE_ENCRYPTION


#define MCUBOOT_VALIDATE_PRIMARY_SLOT
#define MCUBOOT_USE_FLASH_AREA_GET_SECTORS 1


#define MCUBOOT_WATCHDOG_FEED()         \
    do {                                \
        /* TODO: to be implemented */   \
    } while (0)

//#ifdef DEBUG
#define MCUBOOT_HAVE_LOGGING 1
//#else
//#undef MCUBOOT_HAVE_LOGGING
//#endif //DEBUG



#endif /* MCUBOOT_CONFIG_H */
