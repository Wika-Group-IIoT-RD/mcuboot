#ifndef KEY_H
#define KEY_H

// be careful LENGTH_PRIVATE_KEY = 138/8 = 7. need to change if LENGTH_PRIVATE_KEY is no more multiple of 8
#define LENGTH_PRIVATE_KEY			(138)

extern unsigned char __attribute__((section(".keys"))) enc_priv_key[LENGTH_PRIVATE_KEY];


#endif /* !KEY_H */




