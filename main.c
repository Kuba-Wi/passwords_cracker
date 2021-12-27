#include "passwords_cracker.h"

#include <stdio.h>
#include <string.h>

int main() {
    passwords_cracker cracker;
    init_cracker(&cracker);

    load_passwords_and_dictionary(&cracker);
    start_consumer(&cracker);
    crack_passwords(&cracker);

    deinit_cracker(&cracker);
}
