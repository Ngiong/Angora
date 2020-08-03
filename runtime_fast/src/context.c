
#include "stdint.h"
#include <stdlib.h>
#include <stdio.h>

// uint32_t __angora_cond_cmpid;
// void __angora_set_cmpid(uint32_t id) { __angora_cond_cmpid = id; }

extern __thread uint32_t __angora_prev_loc;
extern __thread uint32_t __angora_context;

void __angora_reset_context() {
  __angora_prev_loc = 0;
  __angora_context = 0;
}

void __init_argc_argv(int* argc, char **argv[]) {
  *argc = 2;
  char **tmp_argv = malloc(2 * sizeof(*tmp_argv));
  tmp_argv[0] = "Hello";
  tmp_argv[1] = "World!";
  *argv = tmp_argv;
}

int __print_argc_argv(int argc, char *argv[]) {
  printf("Your argc: %d\n", argc);
  for (int i = 0; i < argc; i++) {
    printf("Your argv %d: #%s#\n", i, argv[i]);
  }
  return __old_main(argc, argv);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    perror("Argc & Argv canno be less than 2.");
    return 1;
  }

  FILE *raw = fopen(argv[1], "rb");
  if (raw == NULL) {
    perror("Cannot open file argv[1]");
    return 1;
  }

  char new_name[100];
  strcpy(new_name, argv[1]);
  strcat(new_name, "p");

  FILE *result = fopen(new_name, "wb");
  if (result == NULL) {
    perror("Cannot open file to write output");
    exit(1);
  }

  int c, prev;
  int buffer[1000], i = 0, j = 0;
  int get_opt_state = 1;
  while ((c = fgetc(raw)) != EOF) {
    if (get_opt_state) {
      if (i > 0 && prev == '\0' && c == '\0') {
        get_opt_state = 0;
      } else {
        buffer[i++] = c;
      }
    } else {
      fputc(c, result);
    }
    prev = c;
  }

  fclose(raw);
  fclose(result);

  unsigned char uc_buffer[1000];
  int len = i;
  for (i = 0; i < len; i++) {
    uc_buffer[i] = buffer[i];
  }

  // count how many opt in the buffer
  i = 0;
  int in_flag = 1, count_opt = 0;
  int new_argc = 0;
  char *new_argv[1000];
  new_argv[new_argc++] = argv[0];

  // make sure we start in_flag (non-whitespace character)
  while (uc_buffer[i] == ' ') i++;
  new_argv[new_argc++] = uc_buffer + i;
  
  for (; i < len; i++) {
    int is_delimiter = uc_buffer[i] == ' ' || uc_buffer[i] == '\0';
    if (in_flag == 1) {
      if (is_delimiter) {
        uc_buffer[i] = '\0';
        in_flag = 0;
        count_opt++;
      } else {
        // do nothing
      }
    } else {
      if (!is_delimiter) {
        new_argv[new_argc++] = uc_buffer + i;
        in_flag = 1;
      } else {
        // do nothing
      }
    }
  }

  new_argv[new_argc++] = new_name;
  return __print_argc_argv(new_argc, new_argv);
}