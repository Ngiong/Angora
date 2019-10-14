#include <utmp.h>
#include <stdio.h>
#include <stdlib.h>
int main() {
  struct utmp *u;
  while((u = getutent()))
    {
        FILE *f1 = fopen("utmp0", "wb");
        int r1 = fwrite(u, sizeof (struct utmp), 1, f1);
        fclose(f1);

        break;
    }
  endutent();
}
