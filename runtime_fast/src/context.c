
#include "stdint.h"

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

void __print_argc_argv(int argc, char *argv[]) {
  printf("Your argc: %d\n", argc);
  for (int i = 0; i < argc; i++) {
    printf("Your argv %d: #%s#\n", i, argv[i]);
  }
}