int win(){
    system("/bin/sh\0");
}

void vuln(){
    char *buf[0x20];
    printf("I can give you a secret %llx\n", &vuln);
    puts("Where are we going? : ");
    read(0, buf, 0x200);
    puts("\nok, let's go!\n");
}

int main(){
    setup();
    banner();
    vuln();
}