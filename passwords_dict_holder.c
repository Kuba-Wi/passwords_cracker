#include "passwords_dict_holder.h"

#include <stdio.h>
#include <string.h>

int read_password(passwords_dict_holder* holder, FILE* file) {
    size_t len = 0;
    char* placeholder = NULL;
    char buf[100];
    int result = fscanf(file, "%s", buf);
    if (result <= 0) {
        return result;
    }
    fscanf(file, "%s", holder->passwords[holder->passw_size++]);
    result = getline(&placeholder, &len, file);
    free(placeholder);
    return result;
}

void init_holder(passwords_dict_holder* holder) {
    holder->dictionary = NULL;
    holder->dict_size = 0;
    holder->passw_size = 0;
}

void deinit_holder(passwords_dict_holder* holder) {
    for (size_t i = 0; i < holder->dict_size; ++i) {
        free(holder->dictionary[i]);
    }
    free(holder->dictionary);
}

/*
 * returns 0 on success and -1 on failure
 */
int load_passwords(passwords_dict_holder* holder, const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        printf("Loading passwords failed.\n");
        return -1;
    }
    while (read_password(holder, file) > 0) {}
    fclose(file);
    return 0;
}

/*
 * returns 0 on success and -1 on failure
 */
int load_dictionary(passwords_dict_holder* holder, const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        printf("Loading dictionary failed.\n");
        return -1;
    }
    char buffer[100];
    int word_size = fscanf(file, "%s", buffer);
    while (word_size > 0) {
        holder->dictionary = (char**)realloc(holder->dictionary, ++holder->dict_size * sizeof(char*));
        holder->dictionary[holder->dict_size - 1] = (char*)malloc((strlen(buffer) + 1) * sizeof(char));
        strcpy(holder->dictionary[holder->dict_size - 1], buffer);
        word_size = fscanf(file, "%s", buffer);
    }
    fclose(file);
    return 0;
}
