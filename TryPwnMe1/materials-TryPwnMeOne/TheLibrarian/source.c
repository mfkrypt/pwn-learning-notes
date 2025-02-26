void vuln(){
    char *buf[0x20];
    puts("Again? Where this time? : ");
    read(0, buf, 0x200);
    puts("\nok, let's go!\n");
    }

int main(){
    setup();
    vuln();

}