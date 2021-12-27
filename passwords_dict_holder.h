#ifndef PASSWORDS_DICT_HOLDER
#define PASSWORDS_DICT_HOLDER

#include <stdlib.h>

#define PASSWORDS_COUNT 1000
#define PASSWORD_SIZE 33

typedef struct {
    char passwords[PASSWORDS_COUNT][PASSWORD_SIZE];
    char** dictionary;
    size_t passw_size;
    size_t dict_size;
} passwords_dict_holder;

void init_holder(passwords_dict_holder* holder);
void deinit_holder(passwords_dict_holder* holder);
int load_passwords(passwords_dict_holder* d_reader, const char* filename);
int load_dictionary(passwords_dict_holder* d_reader, const char* filename);

#endif
