int win(){

    system("/bin/sh");
}

void vuln(){
    char *buf[0x20];
    puts("Return to where? : ");
    read(0, buf, 0x200);
    puts("\nok, let's go!\n");
}

int main(){
    setup();
    vuln();
}