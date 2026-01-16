#include <stdio.h>
#include <stdlib.h>
char *payload(const char *path, size_t *out_len) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    perror("fopen");
    return NULL;
  }

  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  rewind(f);

  if (size <= 0) {
    fclose(f);
    return NULL;
  }

  char *buf = malloc(size);
  if (!buf) {
    fclose(f);
    return NULL;
  }

  if (fread(buf, 1, size, f) != (size_t)size) {
    perror("fread");
    fclose(f);
    free(buf);
    return NULL;
  }

  fclose(f);
  *out_len = size;
  return buf;
}
