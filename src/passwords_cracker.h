#pragma once

#include <pthread.h>
#include <stdatomic.h>

#include "passwords_dict_holder.h"

#define PRODUCER_COUNT 3

typedef struct _passwords_cracker {
    passwords_dict_holder passw_dict_holder;
    char** cracked_passws;
    char** cracked_dict;
    size_t cracked_size;
    size_t last_size;

    pthread_t producer1_word_th[PRODUCER_COUNT];
    pthread_t producer2_word_th[PRODUCER_COUNT];
    pthread_t consumer_thread;
    atomic_bool producer1_th_joinable[PRODUCER_COUNT];
    atomic_bool producer2_th_joinable[PRODUCER_COUNT];
    atomic_bool consumer_th_joinable;
    pthread_cond_t cracked_passws_cv;
    pthread_mutex_t cracked_passws_mx;

    atomic_bool stop_threads;
} passwords_cracker;

void init_cracker(passwords_cracker* cracker);
void reinit_cracker_with_old_dict(passwords_cracker* cracker);
void deinit_without_dictionary(passwords_cracker* cracker);
void deinit_cracker(passwords_cracker* cracker);
void load_passwords_from_file(passwords_cracker* cracker, char* filename);
void load_passwords_and_dictionary(passwords_cracker* cracker);
void crack_passwords(passwords_cracker* cracker);
void start_consumer(passwords_cracker* cracker);
void stop_threads(passwords_cracker* cracker);
size_t get_dict_size(passwords_cracker* cracker);
size_t get_passwords_size(passwords_cracker* cracker);
