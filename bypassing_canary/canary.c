#include <stdio.h>
#include <string.h>

void hacked() {
    puts("Wait, how did you get in here?!");
}

void vuln() {
    char buffer[64];

    puts("You'll never beat my state of the art stack protector!");
    gets(buffer);
    printf(buffer);

    puts("\nWho said gets() is dangerous? Good luck with your BOF attack :P");
    gets(buffer);
}

int main() {
    vuln();
}

// Firstly exploit format string vuln, because it reads the input as format string which means we can leak the canary first
// and then get another chance of overflowing (ret2win)