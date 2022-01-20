#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    int thisrow = 0;
    char *read;
    int first = 1;
    char entry[128];
    while (scanf("%s", entry) != EOF) {
        FILE *output = fopen("hex", first ? "w" : "a");
        read = entry;
        if (first) {
            fprintf(output, "   ");
            first = 0;
        }
        thisrow = 0;
        for (int j = 0; j < strlen(entry); j += 2) {
            fprintf(output, " 0x%c%c,", *read, *(read + 1));
            thisrow++;
            read += 2;
            if (thisrow == 8) {
                fprintf(output,"\n   ");
                thisrow = 0;
            }
        }
        if (thisrow > 0) {
            fprintf(output, "\n    ");
        }
        fclose(output);
    }
}
