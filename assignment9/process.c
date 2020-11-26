#include <stdio.h>
#include <unistd.h>

int main()
{
    printf("index 1\n");
    pid_t pid = fork();
    printf("index 2\n");
    
    int data = 1;
    if (pid == -1) {
        printf("can't fork, error\n");
        return -1;
    }
    
    if (pid == 0) {
        data = 2;
    } else {
        data = 3;
    }
    
    printf("data = %d\n", data);
    
    return 0;
}
