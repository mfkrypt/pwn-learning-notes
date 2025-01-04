#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

// gcc -static -z execstack -z norelro -fno-stack-protector -o format1 format1.c
// Ref. https://exploit-exercises.com/protostar/format1/

int target;

void vuln(char *string)
{
  printf(string);
  
  if(target) {
      printf("you have modified the target :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}