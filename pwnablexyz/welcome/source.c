undefined8 main(void)

{
  long *malloc_ret;
  void *buffer;
  long in_FS_OFFSET;
  size_t length;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  setup();

  puts("Welcome.");
  malloc_ret = (long *)malloc(262144);
  *malloc_ret = 1;

  __printf_chk(1,"Leak: %p\n",malloc_ret);
  __printf_chk(1,"Length of your message: ");

  length = 0;
  __isoc99_scanf(&DAT_00100c50,&length);
  buffer = malloc(length);
  __printf_chk(1,"Enter your message: ");

  read(0,buffer,length);
  *(undefined *)((long)buffer + (length - 1)) = 0;

  write(1,buffer,length);
  if (*malloc_ret == 0) {
    system("cat /flag");
  }

  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }

  return 0;
}