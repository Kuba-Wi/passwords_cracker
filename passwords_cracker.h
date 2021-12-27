#ifndef PASSWORDS_CRACKER
#define PASSWORDS_CRACKER

#include "passwords_dict_holder.h"

#define WORD_SIZE 100

typedef struct {
    char cracked_passws[PASSWORDS_COUNT][WORD_SIZE];
    passwords_dict_holder passw_dict_holder;
} passwords_cracker;

void init_cracker(passwords_cracker* cracker);
void deinit_cracker(passwords_cracker* cracker);
void load_passwords_and_dictionary(passwords_cracker* cracker);
void crack_passwords(passwords_cracker* cracker);

#endif
