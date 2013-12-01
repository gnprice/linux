#ifndef __CRYPTOHASH_H
#define __CRYPTOHASH_H

#define SKEIN_STATE_WORDS 8
#define SKEIN_CONTEXT_WORDS 12

void skein_init(uint64_t *context);
void skein_transform_notlast(uint64_t *context, const char *data);
void skein_transform_last(uint64_t *context, const char *data, int len);
void skein_output_block(const uint64_t *context, size_t index, char *out);


#define SHA_DIGEST_WORDS 5
#define SHA_MESSAGE_BYTES (512 /*bits*/ / 8)
#define SHA_WORKSPACE_WORDS 16

void sha_init(__u32 *buf);
void sha_transform(__u32 *digest, const char *data, __u32 *W);


#define MD5_DIGEST_WORDS 4
#define MD5_MESSAGE_BYTES 64

void md5_transform(__u32 *hash, __u32 const *in);

__u32 half_md4_transform(__u32 buf[4], __u32 const in[8]);

#endif
