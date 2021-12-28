#ifndef PASSWORDS_CRACKER
#define PASSWORDS_CRACKER

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

    pthread_t producer_threads[PRODUCER_COUNT];
    atomic_bool producer_th_joinable[PRODUCER_COUNT];
    pthread_t consumer_thread;
    atomic_bool consumer_th_joinable;
    pthread_cond_t cracked_passws_cv;
    pthread_mutex_t cracked_passws_mx;
} passwords_cracker;

void init_cracker(passwords_cracker* cracker);
void deinit_cracker(passwords_cracker* cracker);
void load_passwords_and_dictionary(passwords_cracker* cracker);
void crack_passwords(passwords_cracker* cracker);
void start_consumer(passwords_cracker* cracker);
size_t get_dict_size(passwords_cracker* cracker);
size_t get_passwords_size(passwords_cracker* cracker);

#endif
