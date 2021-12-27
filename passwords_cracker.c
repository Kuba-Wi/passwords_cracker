#include "passwords_cracker.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

void bytes2md5(const char *data, int len, char *md5buf) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_md5();
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);
    for (i = 0; i < md_len; i++) {
        snprintf(&(md5buf[i * 2]), 16 * 2, "%02x", md_value[i]);
    }
}

void init_cracker(passwords_cracker* cracker) {
    init_holder(&cracker->passw_dict_holder);
    for (size_t i = 0; i < PASSWORDS_COUNT; ++i) {
        strcpy(cracker->cracked_passws[i], "");
    }
}

void deinit_cracker(passwords_cracker* cracker) {
    deinit_holder(&cracker->passw_dict_holder);
}

void load_passwords_and_dictionary(passwords_cracker* cracker) {
    // char buffer[100];

    // printf("Input file with paswords:\n");
    // scanf("%s", buffer);
    int result = load_passwords(&cracker->passw_dict_holder, "../passwords1.txt");
    if (result == -1) {
        printf("End of program\n");
        exit(EXIT_FAILURE);
    }

    // printf("Input dictionary file:\n");
    // scanf("%s", buffer);
    result = load_dictionary(&cracker->passw_dict_holder, "../dictionary1.txt");
    if (result == -1) {
        printf("End of program\n");
        exit(EXIT_FAILURE);
    }
}

void crack_passwords(passwords_cracker* cracker) {
    char md5[PASSWORD_SIZE];
    char* dict_buf;
    for (size_t i = 0; i < cracker->passw_dict_holder.dict_size; ++i) {
        dict_buf = cracker->passw_dict_holder.dictionary[i];
        bytes2md5(dict_buf, strlen(dict_buf), md5);
        for (size_t j = 0; j < cracker->passw_dict_holder.passw_size; ++j) {
            if (strcmp(cracker->cracked_passws[j], "") == 0) {
                if (strcmp(cracker->passw_dict_holder.passwords[j], md5) == 0) {
                    strcpy(cracker->cracked_passws[j], dict_buf);
                }
            }
        }
    }
}
