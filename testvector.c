#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

/* Constants from the examples */
#define DCID 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
#define V2_VERSION 0x5a, 0x8e, 0x30, 0x1a, 

const unsigned char example_dcid[] = { DCID };

const int full_pn_len = 8;
const int max_pn_len = 4; // on the wire
const int sample_len = 16;
const int tag_len = 16;
const size_t mss = 1472;
const size_t min_payload_size = 1200;
#define iv_len 12

/********* KEYING STUFF *********/

struct labels {
    char *client;
    char *server;
    char *key;
    char *iv;
    char *hp;
    char *ku;
};

const struct labels labels_v1 = {
    .client = "client in",
    .server = "server in",
    .key = "quic key",
    .iv = "quic iv",
    .hp = "quic hp",
    .ku = "quic ku",
};

const struct labels labels_v2 = {
    .client = "client in",
    .server = "server in",
    .key = "quicv2 key",
    .iv = "quicv2 iv",
    .hp = "quicv2 hp",
    .ku = "quicv2 ku",
};

const unsigned char v1_salt[] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
};
const unsigned char v2_salt[] = {
    0x3a, 0x78, 0x5f, 0xb8, 0xf3, 0x00, 0x98, 0x37,
    0x54, 0x6c, 0x9e, 0x85, 0x70, 0xb6, 0xba, 0xc8,
    0x43, 0xe3, 0xe1, 0x42,
};

/********* INITIAL PACKET STUFF ******** */
const unsigned char crypto_frame[] = {
    0x06, 0x00, 0x40, 0xf1, 0x01, 0x00, 0x00, 0xed,
    0x03, 0x03, 0xeb, 0xf8, 0xfa, 0x56, 0xf1, 0x29,
    0x39, 0xb9, 0x58, 0x4a, 0x38, 0x96, 0x47, 0x2e,
    0xc4, 0x0b, 0xb8, 0x63, 0xcf, 0xd3, 0xe8, 0x68,
    0x04, 0xfe, 0x3a, 0x47, 0xf0, 0x6a, 0x2b, 0x69,
    0x48, 0x4c, 0x00, 0x00, 0x04, 0x13, 0x01, 0x13,
    0x02, 0x01, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, 0x65, 0x78,
    0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
    0x6d, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a,
    0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17,
    0x00, 0x18, 0x00, 0x10, 0x00, 0x07, 0x00, 0x05,
    0x04, 0x61, 0x6c, 0x70, 0x6e, 0x00, 0x05, 0x00,
    0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33,
    0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
    0x93, 0x70, 0xb2, 0xc9, 0xca, 0xa4, 0x7f, 0xba,
    0xba, 0xf4, 0x55, 0x9f, 0xed, 0xba, 0x75, 0x3d,
    0xe1, 0x71, 0xfa, 0x71, 0xf5, 0x0f, 0x1c, 0xe1,
    0x5d, 0x43, 0xe9, 0x94, 0xec, 0x74, 0xd7, 0x48,
    0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00,
    0x0d, 0x00, 0x10, 0x00, 0x0e, 0x04, 0x03, 0x05,
    0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04, 0x08,
    0x05, 0x08, 0x06, 0x00, 0x2d, 0x00, 0x02, 0x01,
    0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01, 0x00,
    0x39, 0x00, 0x32, 0x04, 0x08, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0x05, 0x04, 0x80,
    0x00, 0xff, 0xff, 0x07, 0x04, 0x80, 0x00, 0xff,
    0xff, 0x08, 0x01, 0x10, 0x01, 0x04, 0x80, 0x00,
    0x75, 0x30, 0x09, 0x01, 0x10, 0x0f, 0x08, 0x83,
    0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x06,
    0x04, 0x80, 0x00, 0xff, 0xff,
};

const unsigned char v1_cli_inhdr[] = {
    0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94,
    0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x00,
    0x44, 0x9e, 0x00, 0x00, 0x00, 0x02,
};
const unsigned char v2_cli_inhdr[] = {
    0xd3, V2_VERSION 0x08, 0x83, 0x94,
    0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x00,
    0x44, 0x9e, 0x00, 0x00, 0x00, 0x02,
};

const unsigned char server_payload[] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x40,
    0x5a, 0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0xee,
    0xfc, 0xe7, 0xf7, 0xb3, 0x7b, 0xa1, 0xd1, 0x63,
    0x2e, 0x96, 0x67, 0x78, 0x25, 0xdd, 0xf7, 0x39,
    0x88, 0xcf, 0xc7, 0x98, 0x25, 0xdf, 0x56, 0x6d,
    0xc5, 0x43, 0x0b, 0x9a, 0x04, 0x5a, 0x12, 0x00,
    0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00,
    0x24, 0x00, 0x1d, 0x00, 0x20, 0x9d, 0x3c, 0x94,
    0x0d, 0x89, 0x69, 0x0b, 0x84, 0xd0, 0x8a, 0x60,
    0x99, 0x3c, 0x14, 0x4e, 0xca, 0x68, 0x4d, 0x10,
    0x81, 0x28, 0x7c, 0x83, 0x4d, 0x53, 0x11, 0xbc,
    0xf3, 0x2b, 0xb9, 0xda, 0x1a, 0x00, 0x2b, 0x00,
    0x02, 0x03, 0x04,
};

const unsigned char v1_srv_inhdr[] = {
    0xc1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0,
    0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x00,
    0x40, 0x75, 0x00, 0x01, 
};

const unsigned char v2_srv_inhdr[] = {
    0xd1, V2_VERSION 0x00, 0x08, 0xf0,
    0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x00,
    0x40, 0x75, 0x00, 0x01, 
};

const int long_pn_offset = 18;

/********* RETRY STUFF ******** */

const unsigned char v1_retry_ph[] = {
    // ODCID
    0x08, DCID
    // Retry Packet
    0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0,
    0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
    0x6f, 0x6b ,0x65, 0x6e,
};
const unsigned char v2_retry_ph[] = {
    // ODCID
    0x08, DCID
    // Retry Packet
    0xcf, V2_VERSION 0x00, 0x08, 0xf0,
    0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
    0x6f, 0x6b ,0x65, 0x6e,
};

unsigned char v2_secret[] = {
    0x66, 0xe9, 0x0f, 0xdd, 0x03, 0xdb, 0x03, 0x0d,
    0x5c, 0x80, 0xed, 0xa2, 0x2a, 0x45, 0x45, 0x6c,
    0xf6, 0x64, 0xe3, 0x7f, 0x71, 0x92, 0x51, 0x10,
    0x59, 0x53, 0x35, 0x07, 0x26, 0xa6, 0x09, 0xcd,
};

const unsigned char v1_key[] = {
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};
const unsigned char v2_key[] = {
    0xd4, 0x2c, 0xe5, 0x94, 0x31, 0x6b, 0x51, 0x6e,
    0x9d, 0xb9, 0x72 ,0xac, 0xf7, 0x65, 0x65, 0x05,
};

const unsigned char v1_nonce[] = {
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,     
    0x23, 0x98, 0x25, 0xbb,
};
const unsigned char v2_nonce[] = {
    0xac, 0x3a, 0xac, 0x31, 0x39, 0xc1, 0xf3, 0x3b,
    0x5c, 0x9b, 0x60, 0x91,
};

/*************** SHORT HEADER STUFF ****************/

const unsigned char short_secret[] = {
    0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e,
    0xbe, 0x69, 0x42, 0x27, 0x48, 0xad, 0x00, 0xa1,
    0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0, 0x7d, 0x60,
    0x60, 0xf6, 0x88, 0xf3, 0x0f, 0x21, 0x63, 0x2b,
};

const unsigned int short_pn = 654360564;

const unsigned char short_hdr[] = {
    0x42, 0x00, 0xbf, 0xf4,
};

const unsigned char full_short_pn[] = {
    0x00, 0x00, 0x00, 0x00, 0x27, 0x00, 0xbf, 0xf4,
};

const unsigned int short_pn_offset = 1;

const unsigned char short_payload[] = { 0x01, };

/* Code, should not have to change below this line */

void print_hex(unsigned char *field, size_t len, const char *indent) {
    for (int i = 0; i < len; i++) {
        printf("%02x", *(field + i));
        if (i == len - 1) {
            continue;
        }
        if (!indent && len <= 32) continue;
        if ((i % 16) == 15) {
            if ((len <= 32) || (indent != NULL) || ((i % 32) == 31)) {
                printf("\n");
                if (indent) {
                    printf("%s", indent);
                }
            } else {
                printf(" ");
            }
        }
    }
}

#define HEX(arg) ); print_hex((unsigned char *)arg, sizeof(arg), NULL); printf(
#define HEXLEN(arg, len) ); print_hex((unsigned char *)arg, len, NULL); printf(
#define HEXINDENT(arg, indent) ); \
    print_hex((unsigned char *)arg, sizeof(arg), indent); printf(

void print_retry_packet(int version) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *key, *nonce, *aad;
    unsigned char packet[100];
    int len;
    size_t aad_len;
    if (!ctx) return;
    switch (version) {
    case 1:
        key =  (unsigned char *)v1_key;
        nonce = (unsigned char *)v1_nonce;
        aad = (unsigned char *)v1_retry_ph;
        aad_len = sizeof(v1_retry_ph);
        break;
    case 2:
        key = (unsigned char *)v2_key;
        nonce = (unsigned char *)v2_nonce;
        aad = (unsigned char *)v2_retry_ph;
        aad_len = sizeof(v2_retry_ph);
        break;
    default:
        printf("Invalid version\n");
        break;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) {
        goto fail;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto fail;
    if (EVP_EncryptUpdate(ctx, NULL, &len, aad,  aad_len) != 1) goto fail;
    if (EVP_EncryptFinal(ctx, NULL, &len) != 1) goto fail;
    len = aad_len - sizeof(example_dcid) - 1;
    memcpy(packet, aad + (aad_len - len), len);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, packet + len) < 1)
        goto fail;
    EVP_CIPHER_CTX_free(ctx);
    len += tag_len;
    print_hex(packet, len, NULL);
    return;
fail:
    printf("encryption error\n");
    EVP_CIPHER_CTX_free(ctx);
    return;
}

void generate_label(char *label, char *context, size_t length,
        unsigned char *hkdf_label, size_t *len) {
    const char *tls13 = "tls13 ";
    *(uint16_t *)hkdf_label = htons(length);
    unsigned char *write = hkdf_label + 2;
    *(write++) = strlen(label) + strlen(tls13);
    memcpy(write, tls13, strlen(tls13));
    write += strlen(tls13);
    memcpy(write, label, strlen(label));
    write += strlen(label);
    memcpy(write, context, strlen(context));
    *(write++) = strlen(context);
    *len = (write - hkdf_label);
}

void print_label(char *label, char *context, size_t length) {
    unsigned char hkdf_label[36];
    size_t len;
    generate_label(label, context, length, hkdf_label, &len);
    for (int i = 0; i < len; i++) {
        printf("%02x", hkdf_label[i]);
    }
}

void hkdf_expand_label(const unsigned char *secret, char *label, char *context,
        size_t length, unsigned char *output) {
    unsigned char hkdf_label[36];
    unsigned char result[32];
    size_t label_len, olen = length;
    generate_label(label, context, length, hkdf_label, &label_len);

    EVP_PKEY_CTX  *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) return;
    if (EVP_PKEY_derive_init(ctx) < 1) goto fail;
    if (EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) < 1) {
        printf("setting mode: %s\n", strerror(errno));
        goto fail;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) < 1) goto fail;
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, 32) < 1) goto fail;
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, hkdf_label, label_len) < 1) goto fail;
    if (EVP_PKEY_derive(ctx, result, &olen) < 1) goto fail;
    EVP_PKEY_CTX_free(ctx);
    memcpy(output, result, length);
    return;
fail:
    printf("expand_label failed\n");
    EVP_PKEY_CTX_free(ctx);
    return;
}

struct aes_keys {
    unsigned char key[16];
    unsigned char iv[iv_len];
    unsigned char hp[16];
    unsigned char ku[16];
};

struct chachakeys {
    unsigned char key[32];
    unsigned char iv[iv_len];
    unsigned char hp[32];
    unsigned char ku[32];
};

#define AES_GCM_128 0
#define CHACHA20_POLY1305 2

#define CIPHER(keys, field) ((cipher == CHACHA20_POLY1305) ? \
        ((struct chachakeys *)keys)->field : ((struct aes_keys *)keys)->field)
void derive_keys(int version, const unsigned char *secret, int cipher,
        void *result) {
    size_t len;
    const struct labels *labels = (version == 2) ? &labels_v2 : &labels_v1;

    hkdf_expand_label((const unsigned char *)secret, labels->key, "",
            (cipher == AES_GCM_128) ? 16 : 32, CIPHER(result, key));
    hkdf_expand_label((const unsigned char *)secret, labels->iv, "",
            iv_len, CIPHER(result, iv));
    hkdf_expand_label((const unsigned char *)secret, labels->hp, "",
            (cipher == AES_GCM_128) ? 16 : 32, CIPHER(result, hp));
    hkdf_expand_label((const unsigned char *)secret, labels->ku, "",
            (cipher == AES_GCM_128) ? 16 : 32, CIPHER(result, ku));
    return;
}

struct secrets {
    unsigned char master[32];
    unsigned char client[32];
    unsigned char server[32];
};

void generate_secrets(int version, const struct labels *labels,
        struct secrets *secrets) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    size_t len;

    if (!ctx) return;
    if (EVP_PKEY_derive_init(ctx) < 1) goto fail;
    if (EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) < 1) {
        printf("setting mode: %s\n", strerror(errno));
        goto fail;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) < 1) goto fail;
    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, (version == 2) ? v2_salt : v1_salt,
            sizeof(v2_salt)) < 1) goto fail;
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, example_dcid, sizeof(example_dcid)) < 1)
        goto fail;
    if (EVP_PKEY_derive(ctx, secrets->master, &len) < 1) goto fail;
    EVP_PKEY_CTX_free(ctx);

    hkdf_expand_label(secrets->master, labels->client, "", sizeof(secrets->client),
            secrets->client);

    hkdf_expand_label(secrets->master, labels->server, "", sizeof(secrets->server),
            secrets->server);
    return;
fail:
    EVP_PKEY_CTX_free(ctx);
}

/* Nonce can be null if not needed. */
void encrypt_payload(unsigned char *pt, size_t aad_len, size_t pt_len, unsigned char *ct,
        int cipher, void *keys, unsigned char *short_nonce) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ct_len, pn_len;
    unsigned char local_nonce[iv_len];
    unsigned char full_pn[full_pn_len];
    unsigned char *nonce = short_nonce ? short_nonce : local_nonce;

    if (!ctx) return;
    memcpy(ct, pt, aad_len);
    pn_len = (*pt & 0xf) + 1;
    if (*pt & 0x80) {
        memset(full_pn, 0, sizeof(full_pn));
        memcpy(&full_pn[full_pn_len - pn_len], pt + aad_len - pn_len, pn_len);
    } else {
        memcpy(&full_pn, full_short_pn, sizeof(full_short_pn));
        memcpy(&full_pn[full_pn_len - pn_len], pt + aad_len - pn_len, pn_len);
    } 
    memcpy(nonce, CIPHER(keys, iv), iv_len);
    for (int i = 0; i < sizeof(full_pn); i++) {
        *(nonce + i + iv_len - sizeof(full_pn)) ^= full_pn[i];
    }

    if (EVP_EncryptInit(ctx, (cipher == CHACHA20_POLY1305) ?
             EVP_chacha20_poly1305() : EVP_aes_128_gcm(),
             CIPHER(keys, key), nonce) < 1) goto fail;
    if (EVP_EncryptUpdate(ctx, NULL, &len, pt, aad_len) < 1) goto fail;
    if (EVP_EncryptUpdate(ctx, ct + aad_len, &ct_len, pt + aad_len, pt_len) < 1) goto fail;
    if (EVP_EncryptFinal_ex(ctx, ct + aad_len + ct_len, &len) < 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, ct + aad_len + ct_len) < 1) goto fail;
    return;
fail:
    printf("encrypt_payload failed");
    EVP_CIPHER_CTX_free(ctx);
    return;
}

void protect_header(unsigned char *pkt, size_t cli_hdr_len, int cipher,
        unsigned char *hp, unsigned char *sample, unsigned char *mask) {
    unsigned char ct[32];
    int len, pn_len;
    int pn_offset = (*pkt & 0x80) ? long_pn_offset : short_pn_offset;
    memcpy(sample, pkt + pn_offset + max_pn_len, sample_len);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return;
    if (cipher == AES_GCM_128) {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, hp, NULL) < 1) goto fail;
        if (EVP_EncryptUpdate(ctx, ct, &len, sample, sample_len) < 1) goto fail;
    } else {
        const unsigned char zeros[] = { 0x00, 0x00, 0x00, 0x00, 0x00, };
        if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, hp, sample) < 1) goto fail;
        if (EVP_EncryptUpdate(ctx, ct, &len, zeros, sizeof(zeros)) < 1) goto fail;
    }
    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) < 1) goto fail;
    pn_len = (*pkt & 0xf) + 1;
    memcpy(mask, ct, max_pn_len + 1);
    if (*pkt & 0x80) {
        (*pkt) ^= ((*mask) & 0x0f);
    } else {
        (*pkt) ^= ((*mask) & 0x1f);
    }
    for (int i = 0; i < pn_len; i++) {
        *(pkt + pn_offset + i) ^= *(mask + i + 1);
    }
    EVP_CIPHER_CTX_free(ctx);
    return;
fail:
    printf("AES-ECB failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return;
}

void main (int argc, char *argv[]) {
    if (argc != 2) {
        printf("Must input the version (1 or 2)\n)");
        exit(-1);
    }
    struct aes_keys retry;
    derive_keys(2, v2_secret, AES_GCM_128, &retry);
    if (memcmp(retry.key, v2_key, sizeof(v2_key)) != 0) {
        printf("retry key incorrect: ");
        print_hex(retry.key, sizeof(v2_key), NULL);
        printf("\n");
        exit(1);
    }

    if (memcmp(retry.iv, v2_nonce, sizeof(v2_nonce)) != 0) {
        printf("retry nonce incorrect: ");
        print_hex(retry.iv, sizeof(v2_nonce), NULL);
        printf("\n");
        exit(1);
    }

    int version = atoi(argv[1]);
    struct aes_keys cli, srv;
    struct secrets secrets;
    const struct labels *labels;
    char *key_str, *iv_str, *hp_str;
    const unsigned char *cli_in_hdr, *srv_in_hdr;
    size_t cli_hdr_len, srv_hdr_len;
    unsigned char sample[sample_len], mask[max_pn_len + 1],
            srv_sample[sample_len], srv_mask[max_pn_len + 1],
            short_sample[sample_len], short_mask[max_pn_len + 1];
    unsigned char cli_in_pkt[mss], cli_ct[mss], srv_in_pkt[mss],
            srv_ct[mss], short_pkt[mss], short_ct[mss];

    switch(version) {
    case 1:
        labels = &labels_v1;
        cli_in_hdr = v1_cli_inhdr;
        cli_hdr_len = sizeof(v1_cli_inhdr);
        srv_in_hdr = v1_srv_inhdr;
        srv_hdr_len = sizeof(v1_srv_inhdr);
        break;
    case 2:
        labels = &labels_v2;
        cli_in_hdr = v2_cli_inhdr;
        cli_hdr_len = sizeof(v2_cli_inhdr);
        srv_in_hdr = v2_srv_inhdr;
        srv_hdr_len = sizeof(v2_srv_inhdr);
        break;
    default:
        printf("version %d unsupported\n", version);
        exit(-1);
    }
    generate_secrets(version, labels, &secrets);

    derive_keys(version, (const unsigned char *)secrets.client, AES_GCM_128,
            &cli);
    derive_keys(version, (const unsigned char *)secrets.server, AES_GCM_128,
            &srv);

    memset(cli_in_pkt, 0, sizeof(cli_in_pkt));
    // XXX this will break if the header length changes: payload length wrong
    memcpy(cli_in_pkt, cli_in_hdr, cli_hdr_len);
    memcpy(&cli_in_pkt[cli_hdr_len], crypto_frame, sizeof(crypto_frame));
    encrypt_payload(cli_in_pkt, cli_hdr_len, min_payload_size - cli_hdr_len - tag_len,
            cli_ct, AES_GCM_128, &cli, NULL);
    protect_header(cli_ct, cli_hdr_len, AES_GCM_128, cli.hp, sample, mask);

    memcpy(srv_in_pkt, srv_in_hdr, srv_hdr_len);
    memcpy(&srv_in_pkt[srv_hdr_len], server_payload, sizeof(server_payload));
    encrypt_payload(srv_in_pkt, srv_hdr_len, sizeof(server_payload), srv_ct,
            AES_GCM_128, &srv, NULL);
    protect_header(srv_ct, srv_hdr_len, AES_GCM_128, srv.hp, srv_sample,
            srv_mask);

    struct chachakeys cc_keys;
    unsigned char short_nonce[sizeof(cc_keys.iv)];
    memcpy(short_pkt, short_hdr, sizeof(short_hdr));
    memcpy(&short_pkt[sizeof(short_hdr)], short_payload, sizeof(short_payload));
    size_t short_len = sizeof(short_hdr) + sizeof(short_payload);
    derive_keys(version, short_secret, CHACHA20_POLY1305, &cc_keys);
    encrypt_payload(short_pkt, sizeof(short_hdr), sizeof(short_payload), short_ct,
            CHACHA20_POLY1305, &cc_keys, short_nonce);
    protect_header(short_ct, sizeof(short_hdr), CHACHA20_POLY1305, cc_keys.hp,
            short_sample, short_mask);

    printf("# Sample Packet Protection {#test-vectors}\n"
"\n"
"This section shows examples of packet protection so that implementations can be\n"
"verified incrementally. Samples of Initial packets from both client and server\n"
"plus a Retry packet are defined. These packets use an 8-byte client-chosen\n"
"Destination Connection ID of 0x"HEX(example_dcid)". Some intermediate values are\n"
"included. All values are shown in hexadecimal.\n"
"\n"
"\n"
"## Keys\n"
"\n"
"The labels generated during the execution of the HKDF-Expand-Label function\n"
"(that is, HkdfLabel.label) and part of the value given to the HKDF-Expand\n"
"function in order to produce its output are:\n"
"\n"
"%s:  ", labels->client); print_label(labels->client, "", 32); printf("\n"
"\n"
"%s:  ", labels->server); print_label(labels->server, "", 32); printf("\n"
"\n"
"%s:  ", labels->key); print_label(labels->key, "", 16); printf("\n"
"\n"
"%s:  ", labels->iv); print_label(labels->iv, "", iv_len); printf("\n"
"\n"
"%s:  ", labels->hp); print_label(labels->hp, "", 16); printf("\n"
"\n"
"The initial secret is common:\n"
"\n"
"~~~\n"
"initial_secret = HKDF-Extract(initial_salt, cid)\n"
"    = "HEXINDENT(secrets.master, "      ")"\n"
"~~~\n"
"\n"
"The secrets for protecting client packets are:\n"
"\n"
"~~~\n"
"client_initial_secret\n"
"    = HKDF-Expand-Label(initial_secret, \"%s\",", labels->client); printf(" \"\", 32)\n"
"    = "HEXINDENT(secrets.client, "      ")"\n"
"\n"
"key = HKDF-Expand-Label(client_initial_secret, \"%s\",", labels->key); printf(" \"\", 16)\n"
"    = "HEX(cli.key)"\n"
"\n"
"iv  = HKDF-Expand-Label(client_initial_secret, \"%s\",", labels->iv); printf(" \"\", 12)\n"
"    = "HEX(cli.iv)"\n"
"\n"
"hp  = HKDF-Expand-Label(client_initial_secret, \"%s\",", labels->hp); printf(" \"\", 16)\n"
"    = "HEX(cli.hp)"\n"
"~~~\n"
"\n"
"The secrets for protecting server packets are:\n"
"\n"
"~~~\n"
"server_initial_secret\n"
"    = HKDF-Expand-Label(initial_secret, \"%s\",", labels->server); printf(" \"\", 32)\n"
"    = "HEXINDENT(secrets.server, "      ")"\n"
"\n"
"key = HKDF-Expand-Label(server_initial_secret, \"%s\",", labels->key); printf(" \"\", 16)\n"
"    = "HEX(srv.key)"\n"
"\n"
"iv  = HKDF-Expand-Label(server_initial_secret, \"%s\",", labels->iv); printf(" \"\", 12)\n"
"    = "HEX(srv.iv)"\n"
"\n"
"hp  = HKDF-Expand-Label(server_initial_secret, \"%s\",", labels->hp); printf(" \"\", 16)\n"
"    = "HEX(srv.hp)"\n"
"~~~\n"
"\n"
"\n"
"## Client Initial {#sample-client-initial}\n"
"\n"
"The client sends an Initial packet.  The unprotected payload of this packet\n"
"contains the following CRYPTO frame, plus enough PADDING frames to make a\n"
"1162-byte payload:\n"
"\n"
"~~~\n"
HEX(crypto_frame)"\n"
"~~~\n"
"\n"
"The unprotected header indicates a length of 1182 bytes: the 4-byte packet\n"
"number, 1162 bytes of frames, and the 16-byte authentication tag.  The header\n"
"includes the connection ID and a packet number of 2:\n"
"\n"
"~~~\n"
HEXLEN(cli_in_hdr, cli_hdr_len)"\n"
"~~~\n"
"\n"
"Protecting the payload produces output that is sampled for header protection.\n"
"Because the header uses a 4-byte packet number encoding, the first 16 bytes of\n"
"the protected payload is sampled and then applied to the header as follows:\n"
"\n"
"~~~\n"
"sample = "HEX(sample)"\n"
"\n"
"mask = AES-ECB(hp, sample)[0..4]\n"
"     = "HEXLEN(mask, 5)"\n"
"\n"
"header[0] ^= mask[0] & 0x0f\n"
"     = "HEXLEN(cli_ct, 1)"\n"
"header[18..21] ^= mask[1..4]\n"
"     = "HEXLEN(&cli_ct[18], 4)"\n"
"header = "HEXLEN(cli_ct, cli_hdr_len)"\n"
"~~~\n"
"\n"
"The resulting protected packet is:\n"
"\n"
"~~~\n"
HEXLEN(cli_ct, 1200)"\n"
"~~~\n"
"\n"
"\n"
"## Server Initial\n"
"\n"
"The server sends the following payload in response, including an ACK frame, a\n"
"CRYPTO frame, and no PADDING frames:\n"
"\n"
"~~~\n"
HEX(server_payload)"\n"
"~~~\n"
"\n"
"The header from the server includes a new connection ID and a 2-byte packet\n"
"number encoding for a packet number of 1:\n"
"\n"
"~~~\n"
HEXLEN(srv_in_hdr, srv_hdr_len)"\n"
"~~~\n"
"\n"
"As a result, after protection, the header protection sample is taken starting\n"
"from the third protected byte:\n"
"\n"
"~~~\n"
"sample = "HEX(srv_sample)"\n"
"mask   = "HEX(srv_mask)"\n"
"header = "HEXLEN(srv_ct, srv_hdr_len)"\n"
"~~~\n"
"\n"
"The final protected packet is then:\n"
"\n"
"~~~\n"
HEXLEN(srv_ct, srv_hdr_len + sizeof(server_payload) + tag_len)"\n"
"~~~\n"
"\n"
"\n"
"## Retry\n"
"\n"
"This shows a Retry packet that might be sent in response to the Initial packet\n"
"in {{sample-client-initial}}. The integrity check includes the client-chosen\n"
"connection ID value of 0x8394c8f03e515708, but that value is not\n"
"included in the final Retry packet:\n"
"\n"
"~~~\n");

print_retry_packet(version);
printf("\n"
"~~~\n"
"\n"
"\n"
"## ChaCha20-Poly1305 Short Header Packet\n"
"\n"
"This example shows some of the steps required to protect a packet with\n"
"a short header.  This example uses AEAD_CHACHA20_POLY1305.\n"
"\n"
"In this example, TLS produces an application write secret from which a server\n"
"uses HKDF-Expand-Label to produce four values: a key, an IV, a header\n"
"protection key, and the secret that will be used after keys are updated (this\n"
"last value is not used further in this example).\n"
"\n"
"~~~\n"
"secret\n"
"    = "HEXINDENT(short_secret, "      ")"\n"
"\n"
"key = HKDF-Expand-Label(secret, \"%s", labels->key); printf("\", \"\", 32)\n"
"    = "HEXINDENT(cc_keys.key, "      ")"\n"
"\n"
"iv  = HKDF-Expand-Label(secret, \"%s", labels->iv); printf("\", \"\", 12)\n"
"    = "HEXINDENT(cc_keys.iv, "      ")"\n"
"\n"
"hp  = HKDF-Expand-Label(secret, \"%s", labels->hp); printf("\", \"\", 32)\n"
"    = "HEXINDENT(cc_keys.hp, "      ")"\n"
"\n"
"ku  = HKDF-Expand-Label(secret, \"%s", labels->ku); printf("\", \"\", 32)\n"
"    = "HEXINDENT(cc_keys.ku, "      ")"\n"
"~~~\n"
"\n"
"The following shows the steps involved in protecting a minimal packet with an\n"
"empty Destination Connection ID. This packet contains a single PING frame (that\n"
"is, a payload of just 0x01) and has a packet number of 654360564. In this\n"
"example, using a packet number of length 3 (that is, 49140 is encoded) avoids\n"
"having to pad the payload of the packet; PADDING frames would be needed if the\n"
"packet number is encoded on fewer bytes.\n"
"\n"
"~~~\n"
"pn                 = %d", short_pn); printf(" (decimal)\n"
"nonce              = "HEX(short_nonce)"\n"
"unprotected header = "HEX(short_hdr)"\n"
"payload plaintext  = "HEX(short_payload)"\n"
"payload ciphertext = "HEXLEN(short_ct + sizeof(short_hdr), sizeof(short_payload) + tag_len)"\n"
"~~~\n"
"\n"
"The resulting ciphertext is the minimum size possible. One byte is skipped to\n"
"produce the sample for header protection.\n"
"\n"
"~~~\n"
"sample = "HEX(short_sample)"\n"
"mask   = "HEX(short_mask)"\n"
"header = "HEXLEN(short_ct, sizeof(short_hdr))"\n"
"~~~\n"
"\n"
"The protected packet is the smallest possible packet size of %ld", short_len + tag_len); printf(" bytes.\n"
"\n"
"~~~\n"
"packet = "HEXLEN(short_ct, short_len + tag_len)"\n"
"~~~\n"
"\n"
); // end of printf
}

