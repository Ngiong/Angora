
#include "stdint.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

// uint32_t __angora_cond_cmpid;
// void __angora_set_cmpid(uint32_t id) { __angora_cond_cmpid = id; }

extern __thread uint32_t __angora_prev_loc;
extern __thread uint32_t __angora_context;

void __angora_reset_context() {
  __angora_prev_loc = 0;
  __angora_context = 0;
}

int __print_argc_argv(int argc, char *argv[]) {
  printf("Your argc: %d\n", argc);
  for (int i = 0; i < argc; i++) {
    printf("Your argv %d: #%s#\n", i, argv[i]);
  }
  return dfs$__old_main(argc, argv);
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

  const int MAXB = 32;
  int buffer[MAXB], i = 0, c, buffer_full = 0, evicted;
  while ((c = fgetc(raw)) != EOF) {
    if (buffer_full) {
      evicted = buffer[i];
    }
    buffer[i++] = c;
    if (i == MAXB) {
      buffer_full = 1;
      i = 0;
    }
    if (buffer_full) {
      fputc(evicted, result);
    }
  }

  int *arranged_buffer;
  int tmp_buffer[MAXB], j = 0, ii, tail;
  if (buffer_full) {
    ii = i;
    while (ii < MAXB) {
      tmp_buffer[j++] = buffer[ii];
      ii++;
    }
    ii = 0;
    while (ii < i) {
      tmp_buffer[j++] = buffer[ii];
      ii++;
    }
    assert(j == MAXB);
    arranged_buffer = tmp_buffer;
    tail = MAXB;

  } else {
    arranged_buffer = buffer;
    tail = i;
  }

  // Find last occurence of double \0
  j = tail - 2;
  while (j >= 0) {
    if (arranged_buffer[j] == '\0' && arranged_buffer[j + 1] == '\0') break;
    j--;
  }
  // Write the rest
  for (ii = 0; ii < j; ii++) {
    fputc(arranged_buffer[ii], result);
  }
  j += 2;
  // Shift bytes into buffer's head
  for (ii = 0; j < tail; j++, ii++) {
    arranged_buffer[ii] = arranged_buffer[j];
  }
  arranged_buffer[ii] = '\0';

  fclose(raw);
  fclose(result);

  tail = ii;
  unsigned char uc_buffer[MAXB];
  for (i = 0; i < tail; i++) {
    uc_buffer[i] = arranged_buffer[i];
  }

  // count how many opt in the buffer
  i = 0;
  int in_flag = 1, count_opt = 0;
  int new_argc = 0;
  char *new_argv[MAXB];
  new_argv[new_argc++] = argv[0];

  while (uc_buffer[i] == ' ') i++; // seek first non-whitespace char
  new_argv[new_argc++] = uc_buffer + i;
  
  for (; i < tail; i++) {
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