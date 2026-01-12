#ifndef KEY_H
#define KEY_H


#define LENGTH_PRIVATE_KEY			(138)

extern unsigned char __attribute__((section(".keys"))) enc_priv_key[LENGTH_PRIVATE_KEY];


#endif /* !KEY_H */




