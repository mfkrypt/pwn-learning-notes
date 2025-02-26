int main(){
    setup();
    banner();
    int admin = 0;
    char buf[0x10];

    puts("PLease go ahead and leave a comment :");
    gets(buf);

    if (admin){
        const char* filename = "flag.txt";
        FILE* file = fopen(filename, "r");
        char ch;
        while ((ch = fgetc(file)) != EOF) {
            putchar(ch);
    }
    fclose(file);
    }

    else{
        puts("Bye bye\n");
        exit(1);
    }
}