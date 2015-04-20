
#ifndef __SHA1_H
#define __SHA1_H

#ifdef __cplusplus
extern "C" {
#endif

#define SHA1_BLOCK_SIZE  64
#define SHA1_DIGEST_SIZE 20


typedef struct {
    uint32_t state[SHA1_DIGEST_SIZE/4];
    uint8_t  block[SHA1_BLOCK_SIZE];
    uint64_t count;
    uint32_t index;
} SHA1_CTX;

void SHA1_Init(SHA1_CTX* context);
void SHA1_Update(SHA1_CTX* context, const uint8_t* data, const size_t len);
void SHA1_Final(SHA1_CTX* context, uint8_t digest[SHA1_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* __SHA1_H */
