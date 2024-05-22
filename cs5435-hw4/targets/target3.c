#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void copyFourInts( char *values )
{  
  int intvalues[4];
  memcpy((char*)intvalues, values, sizeof(int)*5);
}

void foo( char* values )
{
  copyFourInts( values );
}

int main(int argc, char* argv[] ) 
{
  if( argc != 2 )
  {
    fprintf(stderr, "meet: argc != 2\n");
    exit(EXIT_FAILURE);
  }
  
  foo( argv[1] );
  return 0;
}

