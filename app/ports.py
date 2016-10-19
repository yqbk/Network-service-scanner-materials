#include <stdio.h>
#include <math.h>

int main()
{
int b,c;
    scanf("%n",&b);
    scanf("%n",&c);
    if (b=0) {
            if (c=0) {
                printf("tozsamosc");
            } else{
                printf("sprzecznosc"); }
    } else {
        int x=-c/b;
        printf("%n",&x); }

    return 0;
}
