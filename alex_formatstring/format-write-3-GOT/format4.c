#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

// gcc -z execstack -z norelro -no-pie -fno-stack-protector -o format4 format4.c
// Ref. https://exploit-exercises.com/protostar/format4/

void hello()
{
  printf("Code execution redirected !\n");
  _exit(1);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printf(buffer);

  exit(1);   
}

int main(int argc, char **argv)
{
  vuln();
}