#include "passwords_cracker.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

typedef struct _crack_args {
    passwords_cracker* cracker;
    size_t begin;
    size_t end;
} crack_args;

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
    for (size_t i = 0; i < get_passwords_size(cracker); ++i) {
        if (strcmp(cracker->passw_dict_holder.passwords[i], md5) == 0) {
            pthread_mutex_lock(&cracker->cracked_passws_mx);

            cracker->cracked_passws = realloc(cracker->cracked_passws, ++cracker->cracked_size * sizeof(char*));
            cracker->cracked_passws[cracker->cracked_size - 1] = malloc(strlen(md5) + 1);
            strcpy(cracker->cracked_passws[cracker->cracked_size - 1], md5);

            cracker->cracked_dict = realloc(cracker->cracked_dict, cracker->cracked_size * sizeof(char*));
            cracker->cracked_dict[cracker->cracked_size - 1] = malloc(strlen(word) + 1);
            strcpy(cracker->cracked_dict[cracker->cracked_size - 1], word);

            pthread_cond_signal(&cracker->cracked_passws_cv);
            pthread_mutex_unlock(&cracker->cracked_passws_mx);
            }
    }
}

void* producer_crack_passwords(void* c_args) {
    crack_args* args = (crack_args*)c_args;

    for (size_t i = args->begin; i < args->end; ++i) {
        compare_word_with_passwords(args->cracker, args->cracker->passw_dict_holder.dictionary[i]);
    }

    size_t number = 0;
    const size_t space_for_numbers = 50;
    char word[WORD_SIZE + space_for_numbers];
    while (1) {
        for (size_t i = 0; i < get_dict_size(args->cracker); ++i) {
            sprintf(word, "%ld%s%ld", number, args->cracker->passw_dict_holder.dictionary[i], number);
            compare_word_with_passwords(args->cracker, word);
        }
        ++number;
    }

    free(args);
    return 0;
}

void* start_consumer_thread(void* crack) {
    passwords_cracker* cracker = crack;

    pthread_mutex_lock(&cracker->cracked_passws_mx);
    while(1) {
        while (cracker->last_size == cracker->cracked_size) {
            pthread_cond_wait(&cracker->cracked_passws_cv, &cracker->cracked_passws_mx);
        }
        for (size_t i = cracker->last_size; i < cracker->cracked_size; ++i) {
            printf("%s is %s\n", cracker->cracked_passws[i], 
                                 cracker->cracked_dict[i]);
        }

        cracker->last_size = cracker->cracked_size;
    }
    pthread_mutex_unlock(&cracker->cracked_passws_mx);

    return 0;
}

void init_cracker(passwords_cracker* cracker) {
    init_holder(&cracker->passw_dict_holder);
    cracker->cracked_passws = NULL;
    cracker->cracked_dict = NULL;
    cracker->cracked_size = 0;
    cracker->last_size = 0;
    pthread_mutex_init(&cracker->cracked_passws_mx, NULL);
    pthread_cond_init(&cracker->cracked_passws_cv, NULL);
}

void deinit_cracker(passwords_cracker* cracker) {
    for (size_t i = 0; i < PRODUCER_COUNT; ++i) {
        pthread_join(cracker->producer_threads[i], NULL);
    }
    pthread_join(cracker->consumer_thread, NULL);
    pthread_mutex_destroy(&cracker->cracked_passws_mx);
    pthread_cond_destroy(&cracker->cracked_passws_cv);
    for (size_t i = 0; i < cracker->cracked_size; ++i) {
        free(cracker->cracked_passws[i]);
    }
    free(cracker->cracked_passws);
    for (size_t i = 0; i < cracker->cracked_size; ++i) {
        free(cracker->cracked_dict[i]);
    }
    free(cracker->cracked_dict);
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
    for (size_t i = 0; i < PRODUCER_COUNT; ++i) {
        crack_args* args = malloc(sizeof(crack_args));
        args->cracker = cracker;
        args->begin = i * (get_dict_size(cracker) / PRODUCER_COUNT);
        args->end = (i + 1) * (get_dict_size(cracker) / PRODUCER_COUNT);
        if (i == PRODUCER_COUNT - 1) {
            args->end += get_dict_size(cracker) % PRODUCER_COUNT;
        }
        pthread_create(&cracker->producer_threads[i], NULL, producer_crack_passwords, (void*)args);
    }
}

void start_consumer(passwords_cracker* cracker) {
    pthread_create(&cracker->consumer_thread, NULL, start_consumer_thread, (void*)cracker);
}

size_t get_dict_size(passwords_cracker* cracker) {
    return cracker->passw_dict_holder.dict_size;
}

size_t get_passwords_size(passwords_cracker* cracker) {
    return cracker->passw_dict_holder.passw_size;
}
