#include "passwords_cracker.h"

#include <stdio.h>
#include <string.h>

int main() {
    passwords_cracker cracker;
    init_cracker(&cracker);
    load_passwords_and_dictionary(&cracker);
    crack_passwords(&cracker);

    for (size_t i = 0; i < cracker.passw_dict_holder.passw_size; ++i) {
        if (strcmp(cracker.cracked_passws[i], "") != 0)
            printf("%s is %s\n", cracker.passw_dict_holder.passwords[i], cracker.cracked_passws[i]);
    }

    deinit_cracker(&cracker);
}
