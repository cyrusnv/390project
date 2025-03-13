#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

// This function will be called by the tracer
int target_function(int x) {
    printf("Hello from target_function! Got value: %d\n", x);
    return x * 2;
}

int main() {
    printf("Target process running. PID: %d\n", getpid());
    printf("Target entering main loop...\n");
    
    // Just return normally, the tracer will call our function
    return 0;
}