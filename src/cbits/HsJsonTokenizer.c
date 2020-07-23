#include "jsmn.h"

#include <stdlib.h>
#include <errno.h>

int tokenize_json(const char* js, size_t jslen, jsmntok_t** out) {
  int r;

  jsmn_parser parser;
  jsmntok_t* tokens;
  size_t tokcount = 16;

  jsmn_init(&parser);

  tokens = malloc(sizeof(jsmntok_t) * tokcount);
  if (tokens == NULL) {
    return -ENOMEM;
  }

again:
  r = jsmn_parse(&parser, js, jslen, tokens, tokcount);
  if (r >= 0) {
    jsmntok_t* guard;
    if (tokcount == r) {
      tokens = realloc(tokens, sizeof(jsmntok_t) * (tokcount + 1));
      if (tokens == NULL) {
        return -ENOMEM;
      }
    }
    guard = &tokens[r];
    guard->type = JSMN_UNDEFINED;
    guard->size = 0;

    *out = tokens;

  } else if (r == JSMN_ERROR_NOMEM) {
    tokcount = tokcount * 2;
    tokens = realloc(tokens, sizeof(jsmntok_t) * tokcount);
    if (tokens == NULL) {
      return -ENOMEM;
    }
    goto again;
  } else {
    free(tokens);
    r = -EINVAL;
  }

  return r;
}
