#include <stdio.h>
int x; 
int main()
{
    int y,z,t;
    scanf("%d%d%d",&x,&y,&z);
    if (x>y) { 
        t=x;x=y;y=t;
    }
    if(x>z) { 
        t=z;z=x;x=t;
    }
    if(y>z) { 
        t=y;y=z;z=t;
    }
    printf("%d %d %d\n",x,y,z);
}
