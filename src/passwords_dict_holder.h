#pragma once

#include <stdlib.h>

#define PASSWORDS_COUNT 1000
#define PASSWORD_SIZE 33
#define WORD_SIZE 100

typedef struct _passwords_dict_holder {
    char passwords[PASSWORDS_COUNT][PASSWORD_SIZE];
    char** dictionary;
    size_t passw_size;
    size_t dict_size;
} passwords_dict_holder;

void init_holder(passwords_dict_holder* holder);
void reinit_with_old_dict(passwords_dict_holder* holder);
void free_dictionary(passwords_dict_holder* holder);
int load_passwords(passwords_dict_holder* d_reader, const char* filename);
int load_dictionary(passwords_dict_holder* d_reader, const char* filename);
