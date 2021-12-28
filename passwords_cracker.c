#include "passwords_cracker.h"

#include <openssl/evp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

atomic_size_t AT_CRACKED_PASSWS = 0;
size_t ALL_PASSWORDS = 0;

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
    sigset_t signal_mask;
    sigemptyset(&signal_mask);
    sigaddset(&signal_mask, SIGHUP);
    int result = pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
    if (result != 0) {
        printf("Blocking SIGHUP on thread failed.\n");
    }

    crack_args* args = (crack_args*)c_args;

    for (size_t i = args->begin; i < args->end; ++i) {
        compare_word_with_passwords(args->cracker, args->cracker->passw_dict_holder.dictionary[i]);
    }

    size_t first_num, second_num;
    size_t min = 0;
    size_t max = 10;
    const size_t space_for_numbers = 50;
    char word[WORD_SIZE + space_for_numbers];
    while (1) {
        for (size_t i = args->begin; i < args->end; ++i) {
            for (first_num = min; first_num < max; ++first_num) {
                sprintf(word, "%ld%s", first_num, args->cracker->passw_dict_holder.dictionary[i]);
                compare_word_with_passwords(args->cracker, word);

                sprintf(word, "%s%ld", args->cracker->passw_dict_holder.dictionary[i], first_num);
                compare_word_with_passwords(args->cracker, word);

                for (second_num = min; second_num < max; ++second_num) {
                    sprintf(word, "%ld%s%ld", first_num, args->cracker->passw_dict_holder.dictionary[i], second_num);
                    compare_word_with_passwords(args->cracker, word);
                }
            }
        }
        min = max;
        max *= 10;
    }

    free(args);
    return 0;
}

void sighup_handler(__attribute__((unused)) int signum) {
    printf("Cracked passwords: %ld, passwords left: %ld\n", 
           AT_CRACKED_PASSWS, 
           ALL_PASSWORDS - AT_CRACKED_PASSWS);
}

void* start_consumer_thread(void* crack) {
    struct sigaction signal_action;
    signal_action.sa_handler = sighup_handler;
    signal_action.sa_flags = 0;
    sigemptyset(&signal_action.sa_mask);
    int result = sigaction(SIGHUP, &signal_action, NULL);
    if (result == -1) {
        printf("Setting signal handler failed\n");
    }

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
        AT_CRACKED_PASSWS = cracker->cracked_size;
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

    for (size_t i = 0; i < PRODUCER_COUNT; ++i) {
        cracker->producer_th_joinable[i] = false;
    }
    cracker->consumer_th_joinable = false;
}

void deinit_cracker(passwords_cracker* cracker) {
    for (size_t i = 0; i < PRODUCER_COUNT; ++i) {
        if (cracker->producer_th_joinable[i]) {
            pthread_join(cracker->producer_threads[i], NULL);
        }
    }
    if (cracker->consumer_th_joinable) {
        pthread_join(cracker->consumer_thread, NULL);
    }

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
    char buffer[WORD_SIZE];

    printf("Input file with paswords:\n");
    int result = scanf("%s", buffer);
    if (result == EOF) {
        printf("Reading from input failed.\nEnd of program\n");
        exit(EXIT_FAILURE);
    }
    result = load_passwords(&cracker->passw_dict_holder, buffer);
    if (result == -1) {
        printf("End of program\n");
        exit(EXIT_FAILURE);
    }

    printf("Input dictionary file:\n");
    result = scanf("%s", buffer);
    if (result == EOF) {
        printf("Reading from input failed.\nEnd of program\n");
        exit(EXIT_FAILURE);
    }
    result = load_dictionary(&cracker->passw_dict_holder, buffer);
    if (result == -1) {
        printf("End of program\n");
        exit(EXIT_FAILURE);
    }

    ALL_PASSWORDS = get_passwords_size(cracker);
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
        pthread_create(&cracker->producer_threads[i], NULL, producer_crack_passwords, args);
        cracker->producer_th_joinable[i] = true;
    }
}

void start_consumer(passwords_cracker* cracker) {
    pthread_create(&cracker->consumer_thread, NULL, start_consumer_thread, cracker);
    cracker->consumer_th_joinable = true;
}

size_t get_dict_size(passwords_cracker* cracker) {
    return cracker->passw_dict_holder.dict_size;
}

size_t get_passwords_size(passwords_cracker* cracker) {
    return cracker->passw_dict_holder.passw_size;
}
