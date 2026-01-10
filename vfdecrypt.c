/*
 * Copyright (c) 2006
 * Ralf-Philipp Weinmann <ralf@coderpunks.org>
 * Jacob Appelbaum <jacob@appelbaum.net>
 * Christian Fromme <kaner@strace.org>
 *
 * Decrypt a AES-128 encrypted disk image given the encryption key
 * and the hmacsha1key of the image. These two keys can be found
 * out by running hdiutil attach with -debug on the disk image.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
/* 
 * Based on: vfdecrypt (MIT, 2006) by R.-P. Weinmann, J. Appelbaum, C. Fromme.
 * Modernization & fixes (OpenSSL 3 EVP, portability, warnings, bugfix in v2 unwrap)
 * by Eduard Pană edipana0409@gmail.com for Malus Security, 2025.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
#include <openssl/core_names.h>
#include <openssl/params.h>
#endif

#ifdef __APPLE__
    #include <libkern/OSByteOrder.h>

    #define OSSwapHostToBigInt32(x) OSSwapInt32(x)
    #define OSSwapHostToBigInt64(x) OSSwapInt64(x)

#else
    #include <byteswap.h>

    #define OSSwapHostToBigInt32(x) bswap_32(x)
    #define OSSwapHostToBigInt64(x) bswap_64(x)

#endif

/* length of message digest output in bytes (160 bits) */
#define MD_LENGTH               20
/* length of cipher key in bytes (128 bits) */
#define CIPHER_KEY_LENGTH       16
/* block size of cipher in bytes (128 bits) */
#define CIPHER_BLOCKSIZE        16
/* number of iterations for PBKDF2 key derivation */
#define PBKDF2_ITERATION_COUNT  1000

typedef struct {
  /* 0x000: */ uint8_t  filler1[48];
  /* 0x034: */ uint32_t kdf_iteration_count;
  /* 0x034: */ uint32_t kdf_salt_len;
  /* 0x038: */ uint8_t  kdf_salt[48]; /* salt value for key derivation */
  /* 0x068: */ uint8_t  unwrap_iv[32]; /* IV for encryption-key unwrapping */
  /* 0x088: */ uint32_t len_wrapped_aes_key;
  /* 0x08c: */ uint8_t  wrapped_aes_key[296];
  /* 0x1b4: */ uint32_t len_hmac_sha1_key;
  /* 0x1b8: */ uint8_t  wrapped_hmac_sha1_key[300];
  /* 0x1b4: */ uint32_t len_integrity_key;
  /* 0x2e8: */ uint8_t  wrapped_integrity_key[48];
  /* 0x318: */ uint8_t  filler6[484];
} cencrypted_v1_header;

typedef struct {
  unsigned char sig[8];
  uint32_t version;
  uint32_t enc_iv_size;
  uint32_t unk1;
  uint32_t unk2;
  uint32_t unk3;
  uint32_t unk4;
  uint32_t unk5;
  unsigned char uuid[16];
  uint32_t blocksize;
  uint64_t datasize;
  uint64_t dataoffset;
  uint8_t filler1[0x260];
  uint32_t kdf_algorithm;
  uint32_t kdf_prng_algorithm;
  uint32_t kdf_iteration_count;
  uint32_t kdf_salt_len; /* in bytes */
  uint8_t  kdf_salt[32];
  uint32_t blob_enc_iv_size;
  uint8_t  blob_enc_iv[32];
  uint32_t blob_enc_key_bits;
  uint32_t blob_enc_algorithm;
  uint32_t blob_enc_padding;
  uint32_t blob_enc_mode;
  uint32_t encrypted_keyblob_size;
  uint8_t  encrypted_keyblob[0x30];
} cencrypted_v2_pwheader;

void print_hex(uint8_t * /* data */, uint32_t /* len */);
void convert_hex(char * /* str */, uint8_t * /* bytes */,
                 int /* maxlen */);
void dump_v2_header(void * /* hdr */);
void adjust_v1_header_byteorder(cencrypted_v1_header * /* hdr */);
void adjust_v2_header_byteorder(cencrypted_v2_pwheader * /* pwhdr */);

void print_hex(uint8_t *data, uint32_t len) {
  uint32_t ctr;
  const char *sep;

  if (len > 64) len = 64;

  for(ctr = 0; ctr < len; ctr++) {
    sep = (((ctr&7)==0)&&ctr) ? "\n" : "";
    fprintf(stderr, "%s%02x ", sep, data[ctr]);
  }
  fprintf(stderr, "\n\n");
}

void convert_hex(char *str, uint8_t *bytes, int maxlen) {
  int rpos, wpos = 0;

  while(wpos < maxlen) bytes[wpos++] = 0;
  wpos = 0;

  for(rpos = 0; rpos < maxlen; rpos++) {
    /* read two hex chars per byte */
    sscanf(&str[rpos*2], "%2hhx", &bytes[wpos++]);
  }
}

void dump_v2_header(void *hdr) {
  cencrypted_v2_pwheader *pwhdr = (cencrypted_v2_pwheader *) hdr;

  fprintf(stderr, "sig\t%8s\n", pwhdr->sig);
  fprintf(stderr, "blocksize\t%u\n", (unsigned)pwhdr->blocksize);
  fprintf(stderr, "datasize\t%" PRIu64 "\n", (uint64_t)pwhdr->datasize);
  fprintf(stderr, "dataoffset\t%" PRIu64 "\n", (uint64_t)pwhdr->dataoffset);

  /* 103: CSSM_ALGID_PKCS5_PBKDF2 */
  fprintf(stderr, "keyDerivationAlgorithm      %lu\n", (unsigned long) pwhdr->kdf_algorithm);
  fprintf(stderr, "keyDerivationPRNGAlgorithm  %lu\n", (unsigned long) pwhdr->kdf_prng_algorithm);
  /* by default the iteration count should be 1000 iterations */
  fprintf(stderr, "keyDerivationIterationCount %lu\n", (unsigned long) pwhdr->kdf_iteration_count);
  fprintf(stderr, "keyDerivationSaltSize       %lu\n", (unsigned long) pwhdr->kdf_salt_len);
  fprintf(stderr, "keyDerivationSalt           \n");
  print_hex(pwhdr->kdf_salt, pwhdr->kdf_salt_len);
  fprintf(stderr, "blobEncryptionIVSize        %lu\n", (unsigned long) pwhdr->blob_enc_iv_size);
  fprintf(stderr, "blobEncryptionIV            \n");
  print_hex(pwhdr->blob_enc_iv, pwhdr->blob_enc_iv_size);
  fprintf(stderr, "blobEncryptionKeySizeInBits %lu\n",  (unsigned long) pwhdr->blob_enc_key_bits);
  /*  17: CSSM_ALGID_3DES_3KEY_EDE */
  fprintf(stderr, "blobEncryptionAlgorithm     %lu\n",  (unsigned long) pwhdr->blob_enc_algorithm);
  /*   7: CSSM_PADDING_PKCS7 */
  fprintf(stderr, "blobEncryptionPadding       %lu\n",  (unsigned long) pwhdr->blob_enc_padding);
  /*   6: CSSM_ALGMODE_CBCPadIV8 */
  fprintf(stderr, "blobEncryptionMode          %lu\n",  (unsigned long)  pwhdr->blob_enc_mode);
  fprintf(stderr, "encryptedBlobSize           %lu\n",  (unsigned long)  pwhdr->encrypted_keyblob_size);
  fprintf(stderr, "encryptedBlob               \n");
  print_hex(pwhdr->encrypted_keyblob, pwhdr->encrypted_keyblob_size);
}

void adjust_v1_header_byteorder(cencrypted_v1_header *hdr) {
  hdr->kdf_iteration_count = htonl(hdr->kdf_iteration_count);
  hdr->kdf_salt_len = htonl(hdr->kdf_salt_len);
  hdr->len_wrapped_aes_key = htonl(hdr->len_wrapped_aes_key);
  hdr->len_hmac_sha1_key = htonl(hdr->len_hmac_sha1_key);
  hdr->len_integrity_key = htonl(hdr->len_integrity_key);
}

#define swap32(x) x = OSSwapHostToBigInt32(x)
#define swap64(x) x = OSSwapHostToBigInt64(x)

void adjust_v2_header_byteorder(cencrypted_v2_pwheader *pwhdr) {
  swap32(pwhdr->blocksize);
  swap64(pwhdr->datasize);
  swap64(pwhdr->dataoffset);
  pwhdr->kdf_algorithm = htonl(pwhdr->kdf_algorithm);
  pwhdr->kdf_prng_algorithm = htonl(pwhdr->kdf_prng_algorithm);
  pwhdr->kdf_iteration_count = htonl(pwhdr->kdf_iteration_count);
  pwhdr->kdf_salt_len = htonl(pwhdr->kdf_salt_len);
  pwhdr->blob_enc_iv_size = htonl(pwhdr->blob_enc_iv_size);
  pwhdr->blob_enc_key_bits = htonl(pwhdr->blob_enc_key_bits);
  pwhdr->blob_enc_algorithm = htonl(pwhdr->blob_enc_algorithm);
  pwhdr->blob_enc_padding = htonl(pwhdr->blob_enc_padding);
  pwhdr->blob_enc_mode = htonl(pwhdr->blob_enc_mode);
  pwhdr->encrypted_keyblob_size = htonl(pwhdr->encrypted_keyblob_size);
}

/* ---- Crypto contexts (OpenSSL 3 friendly) ---- */
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
static EVP_MAC *g_hmac = NULL;
static EVP_MAC_CTX *g_hmac_ctx = NULL;
/* AES key kept in-process for EVP path */
static uint8_t g_aes_key[CIPHER_KEY_LENGTH];
#else
static HMAC_CTX *hmacsha1_ctx;
static AES_KEY aes_decrypt_key;
#endif

static int CHUNK_SIZE = 4096;  // default

/**
 * Compute IV of current block as
 * truncate128(HMAC-SHA1(hmacsha1key||blockno))
 */
void compute_iv(uint32_t chunk_no, uint8_t *iv) {
  unsigned char mdResult[MD_LENGTH];
  unsigned int mdLen;

  chunk_no = OSSwapHostToBigInt32(chunk_no);
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
  /* re-init with same key and SHA1 digest params */
  if (!EVP_MAC_init(g_hmac_ctx, NULL, 0, NULL)) {
    fprintf(stderr, "EVP_MAC_init (re-init) failed\n");
    exit(1);
  }
  if (!EVP_MAC_update(g_hmac_ctx, (unsigned char *)&chunk_no, sizeof(uint32_t))) {
    fprintf(stderr, "EVP_MAC_update failed\n");
    exit(1);
  }
  size_t outlen = 0;
  if (!EVP_MAC_final(g_hmac_ctx, mdResult, &outlen, sizeof(mdResult))) {
    fprintf(stderr, "EVP_MAC_final failed\n");
    exit(1);
  }
  mdLen = (unsigned int)outlen;
#else
  HMAC_Init_ex(hmacsha1_ctx, NULL, 0, NULL, NULL);
  HMAC_Update(hmacsha1_ctx, (unsigned char *)&chunk_no, sizeof(uint32_t));
  HMAC_Final(hmacsha1_ctx, mdResult, &mdLen);
#endif
  (void)mdLen; /* unused; IV is first 16 bytes of the digest */
  memcpy(iv, mdResult, CIPHER_BLOCKSIZE);
}

void decrypt_chunk(uint8_t *ctext, uint8_t *ptext, uint32_t chunk_no) {
  uint8_t iv[CIPHER_BLOCKSIZE];

  compute_iv(chunk_no, iv);
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) { fprintf(stderr, "EVP_CIPHER_CTX_new failed\n"); exit(1); }
  if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, g_aes_key, iv)) {
    fprintf(stderr, "EVP_DecryptInit_ex failed\n"); exit(1);
  }
  /* No padding: chunks are a multiple of the block size */
  EVP_CIPHER_CTX_set_padding(ctx, 0);
  int outl = 0, tmplen = 0;
  if (!EVP_DecryptUpdate(ctx, ptext, &outl, ctext, CHUNK_SIZE)) {
    fprintf(stderr, "EVP_DecryptUpdate failed\n"); exit(1);
  }
  if (!EVP_DecryptFinal_ex(ctx, ptext + outl, &tmplen)) {
    fprintf(stderr, "EVP_DecryptFinal_ex failed (size mismatch?)\n"); exit(1);
  }
  EVP_CIPHER_CTX_free(ctx);
#else
  AES_cbc_encrypt(ctext, ptext, CHUNK_SIZE, &aes_decrypt_key, iv, AES_DECRYPT);
#endif
}

/* DES3-EDE unwrap operation loosely based on RFC 2630, section 12.6
   wrapped_key has to be 40 bytes in length.  */
int apple_des3_ede_unwrap_key(uint8_t *wrapped_key, int wrapped_key_len,
                              uint8_t *decryptKey, uint8_t *unwrapped_key) {
  uint8_t *TEMP1 = NULL, *TEMP2 = NULL, *CEKICV = NULL;
  uint8_t IV[8] = { 0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05 };
  int outlen = 0, tmplen = 0, i, rc = -1;

  TEMP1 = (uint8_t*)malloc(wrapped_key_len);
  TEMP2 = (uint8_t*)malloc(wrapped_key_len);
  CEKICV = (uint8_t*)malloc(wrapped_key_len);
  if (!TEMP1 || !TEMP2 || !CEKICV) { fprintf(stderr, "Out of memory during key unwrap!\n"); goto cleanup; }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) { fprintf(stderr, "EVP_CIPHER_CTX_new failed\n"); goto cleanup; }

  if (!EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, decryptKey, IV)) {
    fprintf(stderr, "internal error (1) during key unwrap operation!\n"); goto cleanup;
  }
  if (!EVP_DecryptUpdate(ctx, TEMP1, &outlen, wrapped_key, wrapped_key_len)) {
    fprintf(stderr, "internal error (1u) during key unwrap operation!\n"); goto cleanup;
  }
  if (!EVP_DecryptFinal_ex(ctx, TEMP1 + outlen, &tmplen)) {
    fprintf(stderr, "internal error (1f) during key unwrap operation!\n"); goto cleanup;
  }
  outlen += tmplen;

  for (i = 0; i < outlen; i++) TEMP2[i] = TEMP1[outlen - i - 1];

  EVP_CIPHER_CTX_free(ctx); ctx = EVP_CIPHER_CTX_new();
  if (!ctx) { fprintf(stderr, "EVP_CIPHER_CTX_new failed\n"); goto cleanup; }

  if (!EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, decryptKey, TEMP2)) {
    fprintf(stderr, "internal error (2) during key unwrap operation!\n"); goto cleanup;
  }
  tmplen = 0;
  if (!EVP_DecryptUpdate(ctx, CEKICV, &tmplen, TEMP2 + 8, outlen - 8)) {
    fprintf(stderr, "internal error (2u) during key unwrap operation!\n"); goto cleanup;
  }
  outlen = tmplen;
  if (!EVP_DecryptFinal_ex(ctx, CEKICV + outlen, &tmplen)) {
    fprintf(stderr, "internal error (2f) during key unwrap operation!\n"); goto cleanup;
  }
  outlen += tmplen;
  EVP_CIPHER_CTX_free(ctx);
#else
  /* OpenSSL < 1.1.0 fallback */
  EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)malloc(sizeof(*ctx));
  if (!ctx) { fprintf(stderr, "Out of memory for EVP_CIPHER_CTX\n"); goto cleanup; }
  EVP_CIPHER_CTX_init(ctx);
  if (!EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, decryptKey, IV)) {
    fprintf(stderr, "internal error (1) during key unwrap operation!\n"); goto cleanup_old;
  }
  if (!EVP_DecryptUpdate(ctx, TEMP1, &outlen, wrapped_key, wrapped_key_len)) {
    fprintf(stderr, "internal error (1u) during key unwrap operation!\n"); goto cleanup_old;
  }
  if (!EVP_DecryptFinal_ex(ctx, TEMP1 + outlen, &tmplen)) {
    fprintf(stderr, "internal error (1f) during key unwrap operation!\n"); goto cleanup_old;
  }
  outlen += tmplen;
  EVP_CIPHER_CTX_cleanup(ctx);

  for (i = 0; i < outlen; i++) TEMP2[i] = TEMP1[outlen - i - 1];

  EVP_CIPHER_CTX_init(ctx);
  if (!EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, decryptKey, TEMP2)) {
    fprintf(stderr, "internal error (2) during key unwrap operation!\n"); goto cleanup_old;
  }
  if (!EVP_DecryptUpdate(ctx, CEKICV, &outlen, TEMP2 + 8, outlen - 8)) {
    fprintf(stderr, "internal error (2u) during key unwrap operation!\n"); goto cleanup_old;
  }
  if (!EVP_DecryptFinal_ex(ctx, CEKICV + outlen, &tmplen)) {
    fprintf(stderr, "internal error (2f) during key unwrap operation!\n"); goto cleanup_old;
  }
  outlen += tmplen;
  EVP_CIPHER_CTX_cleanup(ctx);
cleanup_old:
  free(ctx);
  if (0) {} /* fall-through to shared cleanup */
#endif

  memcpy(unwrapped_key, CEKICV + 4, outlen - 4);
  rc = 0;

cleanup:
  free(TEMP1); free(TEMP2); free(CEKICV);
  return rc;
}

int unwrap_v1_header(char *passphrase, cencrypted_v1_header *header, uint8_t *aes_key, uint8_t *hmacsha1_key) {
  /* derived key is a 3DES-EDE key */
  uint8_t derived_key[192/8];

  PKCS5_PBKDF2_HMAC_SHA1(passphrase, (int)strlen(passphrase),
                         (unsigned char*)header->kdf_salt, 20,
                         PBKDF2_ITERATION_COUNT, (int)sizeof(derived_key), derived_key);

  if (apple_des3_ede_unwrap_key(header->wrapped_aes_key, 40, derived_key, aes_key) != 0)
    return -1;
  if (apple_des3_ede_unwrap_key(header->wrapped_hmac_sha1_key, 48, derived_key, hmacsha1_key) != 0)
    return -1;

  return 0;
}

int unwrap_v2_header(char *passphrase, cencrypted_v2_pwheader *header, uint8_t *aes_key, uint8_t *hmacsha1_key) {
  /* derived key is a 3DES-EDE key */
  uint8_t derived_key[192/8];
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
#else
  EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)malloc(sizeof(*ctx));
#endif
  uint8_t *TEMP1;
  int outlen = 0, tmplen = 0;

  PKCS5_PBKDF2_HMAC_SHA1(passphrase, (int)strlen(passphrase),
                         (unsigned char*)header->kdf_salt, 20,
                         PBKDF2_ITERATION_COUNT, (int)sizeof(derived_key), derived_key);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  EVP_CIPHER_CTX_init(ctx);
#endif

  /* result of the decryption operation shouldn't be bigger than ciphertext */
  TEMP1 = (uint8_t*)malloc(header->encrypted_keyblob_size);
  if (!TEMP1) { fprintf(stderr, "Out of memory during v2 unwrap!\n"); goto cleanup; }

  /* uses PKCS#7 padding for symmetric key operations by default */
  if (!EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, derived_key, header->blob_enc_iv)) {
    fprintf(stderr, "internal error (v2 init) during key unwrap!\n"); goto cleanup;
  }
  if (!EVP_DecryptUpdate(ctx, TEMP1, &outlen, header->encrypted_keyblob, header->encrypted_keyblob_size)) {
    fprintf(stderr, "internal error (v2 update) during key unwrap!\n"); goto cleanup;
  }
  if (!EVP_DecryptFinal_ex(ctx, TEMP1 + outlen, &tmplen)) {
    fprintf(stderr, "internal error (v2 final) during key unwrap!\n"); goto cleanup;
  }
  outlen += tmplen;

  memcpy(aes_key,      TEMP1,       16);
  memcpy(hmacsha1_key, TEMP1 + 16,  20);

cleanup:
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  if (ctx) EVP_CIPHER_CTX_free(ctx);
#else
  if (ctx) { EVP_CIPHER_CTX_cleanup(ctx); free(ctx); }
#endif
  if (TEMP1) free(TEMP1);
  return 0;
}

int determine_header_version(FILE *dmg) {
  char buf[8];

  fseek(dmg, 0L, SEEK_SET);
  fread(buf, 8, 1, dmg);

  if (!strncmp(buf, "encrcdsa", 8)) return 2;

  fseek(dmg, -8L, SEEK_END);
  fread(buf, 8, 1, dmg);

  if (!strncmp(buf, "cdsaencr", 8)) return 1;
  return -1;
}

int usage(char *message) {
  fprintf(stderr, "%s\n", message);
  fprintf(stderr, "Usage: vfdecrypt -i in-file [-p password] [-k key] -o out-file\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  FILE *in, *out;
  cencrypted_v1_header v1header;
  cencrypted_v2_pwheader v2header;

  uint8_t hmacsha1_key[20], aes_key[16];
  /* CHUNK_SIZE used for buffers — allocate after we may update it */
  uint32_t chunk_no;
  int hdr_version, c, optError = 0;
  char inFile[512], outFile[512], passphrase[512];
  int iflag = 0, oflag = 0, pflag = 0, kflag = 0, verbose = 0;
  extern char *optarg;
  extern int optind, optopt;

  memset(inFile, 0, 512);
  memset(outFile, 0, 512);
  memset(passphrase, 0, 512);

  while((c = getopt(argc, argv, "hvi:o:p:k:")) != -1) {
    switch(c) {
    case 'h':
      usage("Help is on the way. Stay calm.");
      break;
    case 'v':
      verbose++;
      break;
    case 'i':
      if(optarg) strncpy(inFile, optarg, sizeof(inFile)-1);
      iflag = 1;
      break;
    case 'o':
      if (optarg) strncpy(outFile, optarg, sizeof(outFile)-1);
      oflag = 1;
      break;
    case 'p':
      if (optarg) strncpy(passphrase, optarg, sizeof(passphrase)-1);
      pflag = 1;
      break;
    case 'k':
      convert_hex(optarg, aes_key, 16);
      convert_hex(optarg+32, hmacsha1_key, 20);
      kflag=1;
      break;
    case '?':
      fprintf(stderr, "Unknown option: -%c\n", optopt);
      optError++;
      break;
    }
  }

  /* check to see if our user gave incorrect options */
  if (optError) usage("Incorrect arguments.");

  if (strlen(inFile) == 0) {
    in = stdin;
  } else {
    if ((in = fopen(inFile, "rb")) == NULL) {
      fprintf(stderr, "Error: unable to open %s\n", inFile);
      exit(1);
    }
  }

  if (strlen(outFile) == 0) {
    out = stdout;
  } else {
    if ((out = fopen(outFile, "wb")) == NULL) {
      fprintf(stderr, "Error: unable to open %s\n", outFile);
      exit(1);
    }
  }

  if (!pflag && !kflag) {
    fprintf(stderr, "No Passphrase given.\n");
    exit(1);
  }

  hdr_version = determine_header_version(in);

  if (verbose >= 1) {
    if (hdr_version > 0) {
      fprintf(stderr, "v%d header detected.\n", hdr_version);
    } else {
      fprintf(stderr, "unknown format.\n");
      exit(1);
    }
  }

  if (hdr_version == 1) {
    fseek(in, (long) -((long)sizeof(cencrypted_v1_header)), SEEK_END);
    if (fread(&v1header, sizeof(cencrypted_v1_header), 1, in) < 1) {
      fprintf(stderr, "header corrupted?\n"), exit(1);
    }
    adjust_v1_header_byteorder(&v1header);
    if(!kflag) unwrap_v1_header(passphrase, &v1header, aes_key, hmacsha1_key);
  }

  if (hdr_version == 2) {
    fseek(in, 0L, SEEK_SET);
    if (fread(&v2header, sizeof(cencrypted_v2_pwheader), 1, in) < 1) {
      fprintf(stderr, "header corrupted?\n"), exit(1);
    }
    adjust_v2_header_byteorder(&v2header);
    dump_v2_header(&v2header);
    if(!kflag) unwrap_v2_header(passphrase, &v2header, aes_key, hmacsha1_key);
    CHUNK_SIZE = (int)v2header.blocksize;
  }

  /* Prepare crypto contexts */
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
  /* Setup HMAC(SHA1) with the provided key */
  g_hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
  if (!g_hmac) { fprintf(stderr, "EVP_MAC_fetch(HMAC) failed\n"); exit(1); }
  g_hmac_ctx = EVP_MAC_CTX_new(g_hmac);
  if (!g_hmac_ctx) { fprintf(stderr, "EVP_MAC_CTX_new failed\n"); exit(1); }
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA1", 0),
    OSSL_PARAM_END
  };
  if (!EVP_MAC_init(g_hmac_ctx, hmacsha1_key, (size_t)sizeof(hmacsha1_key), params)) {
    fprintf(stderr, "EVP_MAC_init failed\n"); exit(1);
  }
  memcpy(g_aes_key, aes_key, sizeof(g_aes_key));
#else
  /* OpenSSL < 3.0: use legacy HMAC and AES APIs */
# if OPENSSL_VERSION_NUMBER >= 0x10100000L
  hmacsha1_ctx = HMAC_CTX_new();
  if (!hmacsha1_ctx) { fprintf(stderr, "HMAC_CTX_new failed\n"); exit(1); }
# else
  hmacsha1_ctx = (HMAC_CTX*)malloc(sizeof(*hmacsha1_ctx));
  if (!hmacsha1_ctx) { fprintf(stderr, "Out of memory: HMAC CTX!\n"); exit(1); }
  HMAC_CTX_init(hmacsha1_ctx);
# endif
  HMAC_Init_ex(hmacsha1_ctx, hmacsha1_key, (int)sizeof(hmacsha1_key), EVP_sha1(), NULL);
  AES_set_decrypt_key(aes_key, CIPHER_KEY_LENGTH * 8, &aes_decrypt_key);
#endif

  if (verbose >= 1) {
    fprintf(stderr, "AES Key: \n");
    print_hex(aes_key, 16);
    fprintf(stderr, "SHA1 seed: \n");
    print_hex(hmacsha1_key, 20);
  }

  if (hdr_version == 2) fseek(in, (long)v2header.dataoffset, SEEK_SET);
  else fseek(in, 0L, SEEK_SET);

  /* Allocate buffers after CHUNK_SIZE is final */
  uint8_t *inbuf  = (uint8_t*)malloc(CHUNK_SIZE);
  uint8_t *outbuf = (uint8_t*)malloc(CHUNK_SIZE);
  if (!inbuf || !outbuf) { fprintf(stderr, "Out of memory (buffers)\n"); exit(1); }

  chunk_no = 0;
  while(fread(inbuf, CHUNK_SIZE, 1, in) > 0) {
    decrypt_chunk(inbuf, outbuf, chunk_no);
    chunk_no++;
    if(hdr_version == 2 && (v2header.datasize - (uint64_t)ftell(out)) < (uint64_t)CHUNK_SIZE) {
      size_t remain = (size_t)(v2header.datasize - (uint64_t)ftell(out));
      fwrite(outbuf, remain, 1, out);
      break;
    }
    fwrite(outbuf, CHUNK_SIZE, 1, out);
  }

  free(inbuf);
  free(outbuf);

  if (verbose)  fprintf(stderr, "%u chunks written\n", chunk_no);

  /* tidy OpenSSL 3 MAC objects */
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
  EVP_MAC_CTX_free(g_hmac_ctx);
  EVP_MAC_free(g_hmac);
#else
  /* tidy legacy HMAC ctx */
# if OPENSSL_VERSION_NUMBER >= 0x10100000L
  HMAC_CTX_free(hmacsha1_ctx);
# else
  HMAC_CTX_cleanup(hmacsha1_ctx);
  free(hmacsha1_ctx);
# endif
#endif

  /* silence "set but not used" since we parse them but don't branch on them later */
  (void)iflag; (void)oflag;

  return 0;
}
