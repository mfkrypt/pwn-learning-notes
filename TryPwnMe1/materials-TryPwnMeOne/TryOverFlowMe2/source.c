int read_flag(){
        const char* filename = "flag.txt";
        FILE* file = fopen(filename, "r");
        if(!file){
            puts("the file flag.txt is not in the current directory, please contact support\n");
            exit(1);
        }
        char ch;
        while ((ch = fgetc(file)) != EOF) {
        putchar(ch);
    }
    fclose(file);
}

int main(){
    
    setup();
    banner();
    int admin = 0;
    int guess = 1;
    int check = 0;
    char buf[64];

    puts("Please Go ahead and leave a comment :");
    gets(buf);

    if (admin==0x59595959){
            read_flag();
    }

    else{
        puts("Bye bye\n");
        exit(1);
    }
}