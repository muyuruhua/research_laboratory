#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char buf[100];
    FILE *f = NULL;
    
    if (argc > 1) {
        f = fopen(argv[1], "r");
    } else {
        f = stdin;
    }
    
    if (!f) {
        return 1;
    }
    
    if (fgets(buf, sizeof(buf), f)) {
        printf("Read: %s\n", buf);
    }
    
    if (argc > 1) {
        fclose(f);
    }
    
    return 0;
}
