int win(){

    system("/bin/sh\0");

}

int main(){

    setup();

    banner();

    char *username[32];

    puts("Please provide your username\n");

    read(0,username,sizeof(username));

    puts("Thanks! ");

    printf(username);

    puts("\nbye\n");

    exit(1);    

}