#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#define DCID 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,

const unsigned char example_dcid[] = { DCID };

void print_hex(char *label, unsigned char *field, size_t len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", *(field + i));
    }
    printf("\n");
}

/* Constants from the examples */
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
    0xcf, 0x70, 0x9a, 0x50, 0xc4, 0x00, 0x08, 0xf0,
    0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
    0x6f, 0x6b ,0x65, 0x6e,
};

const unsigned char v1_key[] = {
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};
const unsigned char v2_key[] = {
    0xba, 0x85, 0x8d, 0xc7, 0xb4, 0x3d, 0xe5, 0xdb,
    0xf8, 0x76, 0x17, 0xff, 0x4a, 0xb2, 0x53, 0xdb,
};

const unsigned char v1_nonce[] = {
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,     
    0x23, 0x98, 0x25, 0xbb,
};
const unsigned char v2_nonce[] = {
    0x14, 0x1b, 0x99, 0xc2, 0x39, 0xb0, 0x3e, 0x78,
    0x5d, 0x6a, 0x2e, 0x9f,
};

void generate_retry_tag(int version) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *key, *nonce, *aad;
    unsigned char tag[16];
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
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
        goto fail;
    EVP_CIPHER_CTX_free(ctx);
    print_hex("tag", tag, sizeof(tag));
    return;
fail:
    printf("encryption error\n");
    EVP_CIPHER_CTX_free(ctx);
    return;
}

void hkdf_expand_label(unsigned char *secret, char *label, char *context,
        size_t length, unsigned char *output, size_t *olen) {
    const char *tls13 = "tls13 ";
    unsigned char hkdf_label[4 + strlen(tls13) + strlen(label) + strlen(context)];
    unsigned char result[32];
    *(uint16_t *)hkdf_label = htons(length);
    int write = 2;
    hkdf_label[write++] = strlen(label) + strlen(tls13);
    memcpy(&hkdf_label[write], tls13, strlen(tls13));
    write += strlen(tls13);
    memcpy(&hkdf_label[write], label, strlen(label));
    write += strlen(label);
    hkdf_label[write++] = strlen(context);
    memcpy(&hkdf_label[write], context, strlen(context));
    printf("For %s, ", label);
    print_hex("Full label", hkdf_label, sizeof(hkdf_label));

    EVP_PKEY_CTX  *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) return;
    if (EVP_PKEY_derive_init(ctx) < 1) goto fail;
    if (EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) < 1) {
        printf("setting mode: %s\n", strerror(errno));
        goto fail;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) < 1) goto fail;
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, 32) < 1)
        goto fail;
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, hkdf_label,
            sizeof(hkdf_label)) < 1)
        goto fail;
    if (EVP_PKEY_derive(ctx, result, olen) < 1) goto fail;
    EVP_PKEY_CTX_free(ctx);
    memcpy(output, result, length);
    return;
fail:
    printf("expand_label failed\n");
    EVP_PKEY_CTX_free(ctx);
    return;
}

struct keys {
    unsigned char key[16];
    unsigned char iv[12];
    unsigned char hp[16];
};

void derive_keys(int version, unsigned char *secret, struct keys *result) {
    char label[15]; // big enough to take the second part
    size_t len;

    sprintf(label, "%s", (version == 2) ? "quicv2 " : "quic ");
    hkdf_expand_label(secret, strcat(label, "key"), "", sizeof(result->key),
            result->key, &len);
    print_hex("key", result->key, sizeof(result->key));

    sprintf(label, "%s", (version == 2) ? "quicv2 " : "quic ");
    hkdf_expand_label(secret, strcat(label, "iv"), "", sizeof(result->iv),
            result->iv, &len);
    print_hex("iv", result->iv, sizeof(result->iv));

    sprintf(label, "%s", (version == 2) ? "quicv2 " : "quic ");
    hkdf_expand_label(secret, strcat(label, "hp"), "", sizeof(result->hp),
            result->hp, &len);
    print_hex("hp", result->hp, sizeof(result->hp));
    return;
}

const unsigned char v1_salt[] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
};
const unsigned char v2_salt[] = {
    0xa7, 0x07, 0xc2, 0x03, 0xa5, 0x9b, 0x47, 0x18,
    0x4a, 0x1d, 0x62, 0xca, 0x57, 0x04, 0x06, 0xea,
    0x7a, 0xe3, 0xe5, 0xd3,
};

void generate_secrets(int version, struct keys *cli, struct keys *srv) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    unsigned char initial_secret[32], client_initial[32], server_initial[32];
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
    if (EVP_PKEY_derive(ctx, initial_secret, &len) < 1) goto fail;
    EVP_PKEY_CTX_free(ctx);
    print_hex("Initial secret", initial_secret, len);

    printf("CLIENT:\n");
    hkdf_expand_label(initial_secret, "client in", "", sizeof(client_initial),
            client_initial, &len);
    print_hex("client initial", client_initial, sizeof(client_initial));

    derive_keys(version, client_initial, cli);

    printf("\nSERVER:\n");
    hkdf_expand_label(initial_secret, "server in", "", sizeof(server_initial),
            server_initial, &len);
    print_hex("Server initial", server_initial, sizeof(server_initial));

    derive_keys(version, server_initial, srv);
    return;
fail:
    EVP_PKEY_CTX_free(ctx);
}

void main (int argc, char argv[]) {
    const int num_versions = 2;
    struct keys cli[num_versions], srv[num_versions];

    for (int v = 1; v <= num_versions; v++) {
        printf("\n\nV%d INITIAL KEYS\n", v);
        generate_secrets(v, &cli[v-1], &srv[v-1]);

        printf("\n\nV%d RETRY TAG\n", v);
        generate_retry_tag(v);
    }
}

