#include <stdio.h>
#include <unistd.h>
#include <string.h>

void overflow() {
    char option[0x2];
    char name[0x100];  // Who has a name with more than 256 characters?
    int MAGIC = 0xe4ff; // we'll just leave this here.

    while(1) {
        // clear the name buffer 
        memset(name, 0x00, 0x100);

        // read user's name 
        puts("Hey, whats your name!?\n");
        read(STDIN_FILENO, name, 4096);

        // print name back to user
        puts("Welcome ");
        puts(name);

        // ask if the name was correct
        puts("is this name correct? (y/n)?");
        read(STDIN_FILENO, option, 2);

        if(option[0] == 'y' && option[1] == '\n') {
            break;
        }
    }
}

int main() {

    overflow();

    return 0;
}