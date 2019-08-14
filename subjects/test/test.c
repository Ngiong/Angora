#include <stdio.h>
#include <stdlib.h>


int main(int argc, char *argv[]){
  if (argc < 2) return 0;
  char * fn = argv[1];
  FILE * f;
  char x = 0;
  f = fopen(fn, "r");
  char ch = fgetc(f);
  char ch2 = fgetc(f);
  if (ch == 'a'){
    x = 3;
  } else if (ch2 == 'b'){
    x = 2;
  }
  
  if (x == 2){
    x = 10;
  } else {
    x = 20;
  }

  printf("x : %d\n", x);

  return 0;
}
  
