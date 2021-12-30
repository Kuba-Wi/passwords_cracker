#include "passwords_cracker.h"

#include <ctype.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

atomic_size_t AT_CRACKED_PASSWS = 0;
size_t ALL_PASSWORDS = 0;

typedef enum _string_transform_option {
    all_lowercase,
    all_capital,
    first_capital
} string_transform_option;

typedef struct _crack1_word_args {
    passwords_cracker* cracker;
    string_transform_option trans_option;
} crack1_word_args;

typedef struct _crack2_word_args {
    passwords_cracker* cracker;
    char subchar;
} crack2_word_args;

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

void block_sighup_signal() {
    sigset_t signal_mask;
    sigemptyset(&signal_mask);
    sigaddset(&signal_mask, SIGHUP);
    int result = pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
    if (result != 0) {
        printf("Blocking SIGHUP on thread failed.\n");
    }
}

// returns true on success and false on failure
bool transform_word(char* word, string_transform_option trans_option) {
    switch(trans_option) {
        case all_lowercase:
            for (size_t i = 0; i < strlen(word); ++i) {
                word[i] = tolower(word[i]);
            }
            return true;
            break;
        case all_capital:
            word[0] = toupper(word[0]);
            bool has_at_least_one_alpha = false;
            for (size_t i = 1; i < strlen(word); ++i) {
                word[i] = toupper(word[i]);
                if (isalpha(word[i]) > 0) {
                    has_at_least_one_alpha = true;
                }
            }
            return has_at_least_one_alpha;
            break;
        case first_capital:
            if (isalpha(word[0]) == 0) {
                return false;
            }
            word[0] = toupper(word[0]);
            break;
    };
    return true;
}

void* producer1_word_crack_passw(void* c_args) {
    block_sighup_signal();

    crack1_word_args* args = c_args;
    const size_t space_for_numbers = 50;
    char word[WORD_SIZE + space_for_numbers];

    for (size_t i = 0; i < get_dict_size(args->cracker) && !args->cracker->stop_threads; ++i) {
        strcpy(word, args->cracker->passw_dict_holder.dictionary[i]);
        if (transform_word(word, args->trans_option)) {
            compare_word_with_passwords(args->cracker, word);
        }
    }

    char sub_word[WORD_SIZE];
    size_t first, second;
    size_t min = 0;
    size_t max = 10;
    while (!args->cracker->stop_threads) {
        for (size_t i = 0; i < get_dict_size(args->cracker) && !args->cracker->stop_threads; ++i) {
            strcpy(sub_word, args->cracker->passw_dict_holder.dictionary[i]);
            if (!transform_word(sub_word, args->trans_option)) {
                continue;
            }
            for (first = min; first < max && !args->cracker->stop_threads; ++first) {
                sprintf(word, "%ld%s", first, sub_word);
                compare_word_with_passwords(args->cracker, word);

                sprintf(word, "%s%ld", sub_word, first);
                compare_word_with_passwords(args->cracker, word);

                for (second = min; second < max && !args->cracker->stop_threads; ++second) {
                    sprintf(word, "%ld%s%ld", first, sub_word, second);
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

void* producer2_word_crack_passw(void* c_args) {
    block_sighup_signal();

    char word[2 * WORD_SIZE];
    crack2_word_args* args = c_args;
    for (size_t i = 0; i < get_dict_size(args->cracker) && !args->cracker->stop_threads; ++i) {
        for (size_t j = 0; j < get_dict_size(args->cracker) && !args->cracker->stop_threads; ++j) {
            sprintf(word, 
                    "%s%c%s", 
                    args->cracker->passw_dict_holder.dictionary[i],
                    args->subchar,
                    args->cracker->passw_dict_holder.dictionary[j]);
            
            compare_word_with_passwords(args->cracker, word);
        }
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
    signal_action.sa_flags = SA_RESTART; // makes that reading from input (scanf) on main thread isn't interrupted when receiving signal
    sigemptyset(&signal_action.sa_mask);
    int result = sigaction(SIGHUP, &signal_action, NULL);
    if (result == -1) {
        printf("Setting signal handler failed\n");
    }

    passwords_cracker* cracker = crack;

    pthread_mutex_lock(&cracker->cracked_passws_mx);
    while(!cracker->stop_threads) {
        while (cracker->last_size == cracker->cracked_size && !cracker->stop_threads) {
            pthread_cond_wait(&cracker->cracked_passws_cv, &cracker->cracked_passws_mx);
        }

        if (cracker->stop_threads) {
            break;
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

void init_only_cracker(passwords_cracker* cracker) {
    cracker->cracked_passws = NULL;
    cracker->cracked_dict = NULL;
    cracker->cracked_size = 0;
    cracker->last_size = 0;
    pthread_mutex_init(&cracker->cracked_passws_mx, NULL);
    pthread_cond_init(&cracker->cracked_passws_cv, NULL);

    for (size_t i = 0; i < PRODUCER_COUNT; ++i) {
        cracker->producer1_th_joinable[i] = false;
        cracker->producer2_th_joinable[i] = false;
    }
    cracker->consumer_th_joinable = false;
    cracker->stop_threads = false;

    AT_CRACKED_PASSWS = 0;
}

void init_cracker(passwords_cracker* cracker) {
    init_holder(&cracker->passw_dict_holder);
    init_only_cracker(cracker);
}

void reinit_cracker_with_old_dict(passwords_cracker* cracker) {
    reinit_with_old_dict(&cracker->passw_dict_holder);
    init_only_cracker(cracker);
}

void deinit_without_dictionary(passwords_cracker* cracker) {
    for (size_t i = 0; i < PRODUCER_COUNT; ++i) {
        if (cracker->producer1_th_joinable[i]) {
            pthread_join(cracker->producer1_word_th[i], NULL);
        }
        if (cracker->producer2_th_joinable[i]) {
            pthread_join(cracker->producer2_word_th[i], NULL);
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
}

void deinit_cracker(passwords_cracker* cracker) {
    deinit_without_dictionary(cracker);
    free_dictionary(&cracker->passw_dict_holder);
}

void load_passwords_from_file(passwords_cracker* cracker, char* filename) {
    int result = load_passwords(&cracker->passw_dict_holder, filename);
    if (result == -1) {
        printf("End of program\n");
        exit(EXIT_FAILURE);
    }

    ALL_PASSWORDS = get_passwords_size(cracker);
}

void load_passwords_and_dictionary(passwords_cracker* cracker) {
    char buffer[WORD_SIZE];

    printf("Input dictionary file:\n");
    int result = scanf("%s", buffer);
    if (result == EOF) {
        printf("Reading from input failed.\nEnd of program\n");
        exit(EXIT_FAILURE);
    }
    result = load_dictionary(&cracker->passw_dict_holder, buffer);
    if (result == -1) {
        printf("End of program\n");
        exit(EXIT_FAILURE);
    }

    printf("Input file with paswords:\n");
    result = scanf("%s", buffer);
    if (result == EOF) {
        printf("Reading from input failed.\nEnd of program\n");
        exit(EXIT_FAILURE);
    }
    result = load_passwords(&cracker->passw_dict_holder, buffer);
    if (result == -1) {
        printf("End of program\n");
        exit(EXIT_FAILURE);
    }

    ALL_PASSWORDS = get_passwords_size(cracker);
}

void crack_passwords(passwords_cracker* cracker) {
    string_transform_option trans_option[PRODUCER_COUNT] = {all_lowercase, all_capital, first_capital};
    for (size_t i = 0; i < PRODUCER_COUNT; ++i) {
        crack1_word_args* args = malloc(sizeof(crack1_word_args));
        args->cracker = cracker;
        args->trans_option = trans_option[i];
        pthread_create(&cracker->producer1_word_th[i], NULL, producer1_word_crack_passw, args);
        cracker->producer1_th_joinable[i] = true;
    }

    char subchar[PRODUCER_COUNT] = {' ', ';', ':'};
    for (size_t i = 0; i < PRODUCER_COUNT; ++i) {
        crack2_word_args* args = malloc(sizeof(crack2_word_args));
        args->cracker = cracker;
        args->subchar = subchar[i];

        pthread_create(&cracker->producer2_word_th[i], NULL, producer2_word_crack_passw, args);
        cracker->producer2_th_joinable[i] = true;
    }
}

void start_consumer(passwords_cracker* cracker) {
    pthread_create(&cracker->consumer_thread, NULL, start_consumer_thread, cracker);
    cracker->consumer_th_joinable = true;
}

void stop_threads(passwords_cracker* cracker) {
    pthread_mutex_lock(&cracker->cracked_passws_mx);
    cracker->stop_threads = true;
    pthread_cond_signal(&cracker->cracked_passws_cv);
    pthread_mutex_unlock(&cracker->cracked_passws_mx);
}

size_t get_dict_size(passwords_cracker* cracker) {
    return cracker->passw_dict_holder.dict_size;
}

size_t get_passwords_size(passwords_cracker* cracker) {
    return cracker->passw_dict_holder.passw_size;
}
