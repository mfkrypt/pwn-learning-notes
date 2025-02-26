int main(){
    setup();
    banner();
    char *buf[128];   

    puts("\nGive me your shell, and I will execute it: ");
    read(0,buf,sizeof(buf));
    puts("\nExecuting Spell...\n");

    ( ( void (*) () ) buf) ();

}