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

void compare_word_with_passwords(passwords_cracker* cracker, char* word) {
    char md5[PASSWORD_SIZE];
    bytes2md5(word, strlen(word), md5);
    for (size_t j = 0; j < get_passwords_size(cracker); ++j) {
        if (strcmp(cracker->cracked_passws[j], "") == 0) {
            if (strcmp(cracker->passw_dict_holder.passwords[j], md5) == 0) {
                strcpy(cracker->cracked_passws[j], word);
            }
        }
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
    for (size_t i = 0; i < get_dict_size(cracker); ++i) {
        compare_word_with_passwords(cracker, cracker->passw_dict_holder.dictionary[i]);
    }

    size_t number = 0;
    char word[150];
    while (1) {
        for (size_t i = 0; i < get_dict_size(cracker); ++i) {
            sprintf(word, "%ld%s%ld", number, cracker->passw_dict_holder.dictionary[i], number);
            compare_word_with_passwords(cracker, word);
        }
        ++number;
    }
}

size_t get_dict_size(passwords_cracker* cracker) {
    return cracker->passw_dict_holder.dict_size;
}

size_t get_passwords_size(passwords_cracker* cracker) {
    return cracker->passw_dict_holder.passw_size;
}
