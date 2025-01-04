#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

// gcc -z execstack -z norelro -fno-stack-protector -o format1 format1.c

int main(int argc, char *argv[])
{
    int target = 0xdeadc0de;
    char buffer[64];

    fgets(buffer, 64, stdin);
    printf(buffer);

    if(target == 0xcafebabe) {
      	printf("Good job !\n");
      	return EXIT_SUCCESS;
  	} else {
  	  	printf("Nope...\n");
  	  	exit(EXIT_FAILURE);
  	}
}