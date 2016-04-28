/**
  AES encryption/decryption demo program using OpenSSL EVP apis
  gcc -Wall openssl_aes.c -lcrypto

  this is public domain code.

  Saju Pillai (saju.pillai@gmail.com)
**/

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <ccoin/util.h>
#include <ccoin/cstr.h>

#define CCOIN_USE_OPENSSLx

#if defined(CCOIN_USE_OPENSSL)

#include <openssl/evp.h>
#include <openssl/aes.h>

static bool aes_init(const unsigned char *key_data, int key_data_len,
		     const unsigned char *salt, EVP_CIPHER_CTX * e_ctx,
		     EVP_CIPHER_CTX * d_ctx)
{
	int i, nrounds = 1721;
	unsigned char key[32], iv[32];

	/*
	 * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
	 * nrounds is the number of times the we hash the material. More rounds are more secure but
	 * slower.
	 */
	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), salt, key_data,
			   key_data_len, nrounds, key, iv);
	if (i != 32) {
		/* printf("Key size is %d bits - should be 256 bits\n", i); */
		return false;
	}

	EVP_CIPHER_CTX_init(e_ctx);
	EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_CIPHER_CTX_init(d_ctx);
	EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

	return true;
}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
static unsigned char *aes_encrypt(EVP_CIPHER_CTX * e, const unsigned char *plaintext,
			   size_t *len)
{
	/* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
	int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
	unsigned char *ciphertext = malloc(c_len);

	/* allows reusing of 'e' for multiple encryption cycles */
	EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

	/* update ciphertext, c_len is filled with the length of ciphertext generated,
	 *len is the size of plaintext in bytes */
	EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

	/* update ciphertext with the final remaining bytes */
	EVP_EncryptFinal_ex(e, ciphertext + c_len, &f_len);

	*len = c_len + f_len;
	return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
static unsigned char *aes_decrypt(EVP_CIPHER_CTX * e, const unsigned char *ciphertext,
			   size_t *len)
{
	/* because we have padding ON, we must allocate an extra cipher block size of memory */
	int p_len = *len, f_len = 0;
	unsigned char *plaintext = malloc(p_len + AES_BLOCK_SIZE);

	EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
	EVP_DecryptFinal_ex(e, plaintext + p_len, &f_len);

	*len = p_len + f_len;
	return plaintext;
}

cstring *decrypt_aes_buffer(const void *ciphertext,
			    size_t ct_len,
			    const void *key,
			    size_t key_len)
{
	EVP_CIPHER_CTX en, de;
	unsigned int salt[] = { 4185398345U, 2729682459U };
	cstring *rs = NULL;
	if (!aes_init(key, key_len, (unsigned char *) &salt, &en, &de))
		goto out;

	size_t pt_len = ct_len;
	void *plaintext = aes_decrypt(&de, ciphertext, &pt_len);

	rs = cstr_new_buf(plaintext, pt_len);

	EVP_CIPHER_CTX_cleanup(&en);
	EVP_CIPHER_CTX_cleanup(&de);

out:
	return rs;
}


void *encrypt_aes_buffer(const void *plaintext, size_t pt_len,
			 const void *key, size_t key_len,
			 size_t *ct_len)
{
	EVP_CIPHER_CTX en, de;
	unsigned int salt[] = { 4185398345U, 2729682459U };

	if (!aes_init(key, key_len, (unsigned char *) &salt, &en, &de))
		return false;

	*ct_len = pt_len;
	void *ciphertext = aes_encrypt(&en, plaintext, ct_len);

	EVP_CIPHER_CTX_cleanup(&en);
	EVP_CIPHER_CTX_cleanup(&de);

	return ciphertext;
}

#else // defined(CCOIN_USE_OPENSSL)

#include <ccoin/crypto/aes.h>
#include <ccoin/crypto/sha2.h>

/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
static bool ccoin_aes_init(const uint8_t *key_data,
			   int key_data_len,
			   uint8_t *salt_8,
			   uint8_t *iv_32,
			   aes_encrypt_ctx *e_ctx,
			   aes_decrypt_ctx *d_ctx)
{
	int nrounds = 1721;

	/*
	 * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to
	 * hash the supplied key material.  nrounds is the number of
	 * times the we hash the material. More rounds are more secure
	 * but slower.
	 */

	/*
	 * hash^nrounds( key_data || salt )
	 *   == hash^(nrounds-1)( hash(key_data || salt) )
	 */

	uint8_t _hash0[64];
	uint8_t _hash1[64];

	{
		SHA512_CTX ctx;
		sha512_Init(&ctx);
		sha512_Update(&ctx, key_data, key_data_len);
		sha512_Update(&ctx, salt_8, 8);
		sha512_Final(_hash0, &ctx);
	}
	--nrounds;

	uint8_t *tmp;
	uint8_t *hash0 = _hash0;
	uint8_t *hash1 = _hash1;
	while (0 < nrounds)
	{
		sha512_Raw(hash0, 64, hash1);
		tmp = hash1;
		hash1 = hash0;
		hash0 = tmp;

		--nrounds;
	}

	/*
	 * hash0 contains the data.  First 32 bytes are key data, the
	 * last are the IV.
	 */

	aes_encrypt_key256(hash0, e_ctx);
	aes_decrypt_key256(hash0, d_ctx);
	memcpy(iv_32, hash0+32, 32);

	return true;
}

static uint8_t *ccoin_aes_encrypt(aes_encrypt_ctx *ctx,
				  uint8_t *iv,
				  const void *_plaintext,
				  const size_t pt_len,
				  size_t *out_len)
{
	const size_t total_blocks = (pt_len / AES_BLOCK_SIZE) + 1;
	const size_t out_size = total_blocks * AES_BLOCK_SIZE;
	const size_t padding = out_size - pt_len;

	const size_t msg_whole_blocks = total_blocks - 1;
	const size_t msg_remainder_offset = msg_whole_blocks * AES_BLOCK_SIZE;
	const size_t msg_remainder_size = pt_len - msg_remainder_offset;

	/* assert(msg_remainder_size == (AES_BLOCK_SIZE - padding)); */

	uint8_t *out = (uint8_t *)malloc(out_size);
	if (msg_whole_blocks)
	{
		aes_cbc_encrypt(_plaintext, out, msg_remainder_offset, iv, ctx);
	}

	uint8_t final_block[AES_BLOCK_SIZE];
	uint8_t *plaintext = (uint8_t *)_plaintext;
	if (msg_remainder_size)
	{
		memcpy(final_block,
		       plaintext + msg_remainder_offset,
		       msg_remainder_size);
	}

	memset(final_block + msg_remainder_size, (uint8_t )padding, padding);

	aes_cbc_encrypt(final_block,
			&out[msg_remainder_offset],
			AES_BLOCK_SIZE,
			iv,
			ctx);

#if 0
	const size_t whole_blocks = (pt_len + 1) / AES_BLOCK_SIZE;
	const size_t final_block_offset = AES_BLOCK_SIZE * whole_blocks;
	const size_t final_block_size = pt_len - final_block_offset;
	const size_t final_block_padding = AES_BLOCK_SIZE - final_block_size;
	const size_t out_size = (final_block_size)?
		((whole_blocks + 1) * AES_BLOCK_SIZE):(pt_len);

	if (!out)
	{
		return NULL;
	}


	if (final_block_size)
	{
		uint8_t *plaintext = (uint8_t *)_plaintext;
		uint8_t final_block[AES_BLOCK_SIZE];
		memcpy(final_block,
		       plaintext + final_block_offset,
		       final_block_size);
		memset(final_block + final_block_size,
		       (uint8_t )final_block_padding,
		       final_block_padding);

		aes_cbc_encrypt(final_block,
				&out[final_block_offset],
				AES_BLOCK_SIZE,
				iv,
				ctx);
	}
#endif

	*out_len = out_size;
	return out;
}

/*
 * Decrypt *len bytes of ciphertext
 */
static uint8_t *ccoin_aes_decrypt(aes_decrypt_ctx *ctx,
				  uint8_t *iv,
				  const uint8_t *ciphertext,
				  size_t ct_len,
				  size_t *out_len)
{
	if (0 != (ct_len % AES_BLOCK_SIZE)) {
		return NULL;
	}

	uint8_t *out_pt = (uint8_t *)malloc(ct_len);
	if (!out_pt) {
		return NULL;
	}

	aes_cbc_decrypt(ciphertext, out_pt, ct_len, iv, ctx);

	const size_t pad_len = out_pt[ct_len-1];
	if (pad_len > ct_len) {
		free(out_pt);
		return NULL;
	}

	*out_len = ct_len - pad_len;
	return out_pt;
}

void *encrypt_aes_buffer(const void *plaintext, size_t pt_len,
			 const void *key, size_t key_len,
			 size_t *ct_len)
{
	aes_encrypt_ctx e_ctx;
	aes_decrypt_ctx d_ctx;
	uint8_t iv[32];
	unsigned int salt[] = { 4185398345U, 2729682459U };
	if (!ccoin_aes_init(key, key_len, (uint8_t *)salt, iv, &e_ctx, &d_ctx))
	{
		return NULL;
	}

	*ct_len = pt_len;
	return ccoin_aes_encrypt(&e_ctx, iv, plaintext, pt_len, ct_len);
}

cstring *decrypt_aes_buffer(const void *ciphertext,
			    size_t ct_len,
			    const void *key,
			    size_t key_len)
{
	aes_encrypt_ctx e_ctx;
	aes_decrypt_ctx d_ctx;
	uint8_t iv[32];
	unsigned int salt[] = { 4185398345U, 2729682459U };
	if (!ccoin_aes_init(key, key_len, (uint8_t *)salt, iv, &e_ctx, &d_ctx))
	{
		return NULL;
	}

	size_t pt_len = ct_len;
	void *plaintext =
		ccoin_aes_decrypt(&d_ctx, iv, ciphertext, ct_len, &pt_len);
	if (!plaintext)
	{
		return NULL;
	}

	cstring *ret = cstr_new_buf(plaintext, pt_len);
	free(plaintext);

	return ret;
}

#endif // else // defined(CCOIN_USE_OPENSSL)

cstring *read_aes_file(const char *filename, void *key, size_t key_len,
		       size_t max_file_len)
{
	void *ciphertext = NULL;
	size_t ct_len = 0;

	if (!bu_read_file(filename, &ciphertext, &ct_len, max_file_len)) {
		return NULL;
	}

	cstring *rs = decrypt_aes_buffer(ciphertext, ct_len, key, key_len);
	if (!rs) {
		free(ciphertext);
	}

	return rs;
}

bool write_aes_file(const char *filename, void *key, size_t key_len,
		    const void *plaintext, size_t pt_len)
{
	size_t ct_len;
	void *ciphertext =
		encrypt_aes_buffer(plaintext, pt_len, key, key_len, &ct_len);
	if (!ciphertext) {
		return false;
	}

	bool rc = bu_write_file(filename, ciphertext, ct_len);

	free(ciphertext);

	return rc;
}

#if 0
int main(int argc, char **argv)
{
	/* "opaque" encryption, decryption ctx structures that libcrypto uses to record
	   status of enc/dec operations */
	EVP_CIPHER_CTX en, de;

	/* 8 bytes to salt the key_data during key generation. This is an example of
	   compiled in salt. We just read the bit pattern created by these two 4 byte
	   integers on the stack as 64 bits of contigous salt material -
	   ofcourse this only works if sizeof(int) >= 4 */
	unsigned int salt[] = { 12345U, 54321U };
	unsigned char *key_data;
	int key_data_len, i;
	char *input[] =
	    { "a", "abcd", "this is a test", "this is a bigger test",
		"\nWho are you ?\nI am the 'Doctor'.\n'Doctor' who ?\nPrecisely!",
		NULL
	};

	/* the key_data is read from the argument list */
	key_data = (unsigned char *) argv[1];
	key_data_len = strlen(argv[1]);

	/* gen key and iv. init the cipher ctx object */
	if (aes_init
	    (key_data, key_data_len, (unsigned char *) &salt, &en, &de)) {
		printf("Couldn't initialize AES cipher\n");
		return -1;
	}

	/* encrypt and decrypt each input string and compare with the original */
	for (i = 0; input[i]; i++) {
		char *plaintext;
		unsigned char *ciphertext;
		int olen, len;

		/* The enc/dec functions deal with binary data and not C strings. strlen() will
		   return length of the string without counting the '\0' string marker. We always
		   pass in the marker byte to the encrypt/decrypt functions so that after decryption
		   we end up with a legal C string */
		olen = len = strlen(input[i]) + 1;

		ciphertext =
		    aes_encrypt(&en, (unsigned char *) input[i], &len);
		plaintext = (char *) aes_decrypt(&de, ciphertext, &len);

		if (strncmp(plaintext, input[i], olen))
			printf("FAIL: enc/dec failed for \"%s\"\n",
			       input[i]);
		else
			printf("OK: enc/dec ok for \"%s\"\n", plaintext);

		free(ciphertext);
		free(plaintext);
	}

	EVP_CIPHER_CTX_cleanup(&en);
	EVP_CIPHER_CTX_cleanup(&de);

	return 0;
}
#endif
