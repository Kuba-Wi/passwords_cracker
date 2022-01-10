#include "passwords_cracker.h"

#include <stdio.h>
#include <string.h>

int main() {
    passwords_cracker cracker;
    init_cracker(&cracker);

    load_passwords_and_dictionary(&cracker);
    start_consumer(&cracker);
    crack_passwords(&cracker);

    char buffer[WORD_SIZE];
    int result = scanf("%s", buffer);
    while (strcmp(buffer, "q") != 0) {
        if (result == EOF) {
            printf("Reading from input failed.\nEnd of program\n");
            exit(EXIT_FAILURE);
        }

        deinit_without_dictionary(&cracker);
        reinit_cracker_with_old_dict(&cracker);

        load_passwords_from_file(&cracker, buffer);
        start_consumer(&cracker);
        crack_passwords(&cracker);

        result = scanf("%s", buffer);
    }

    deinit_cracker(&cracker);
}
