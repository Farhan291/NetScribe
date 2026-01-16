#include <stdio.h>
#include <string.h>

#include "inject/inject_main.h"
#include "sniff/sniff_main.h"
int main(int argc, char **argv) {
  if (argc < 2) {
    printf("Please Select anyone Option: sniff | inject ");
    return 1;
  }

  if (strcmp(argv[1], "sniff") == 0) {
    return sniff_main(argc - 1, argv + 1);
  } else if (strcmp(argv[1], "inject") == 0) {
    return inject_main(argc - 1, argv + 1);
  } else {
    fprintf(stderr, "Unknown mode: %s\n", argv[1]);
    return 1;
  }
}
