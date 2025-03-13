#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>

// Error handling function, because maybe this will save me.
void error_exit(const char *msg)
{
    perror(msg);
    exit(1);
}

// Call a function in the target process
int call_function(pid_t pid, unsigned long func_addr, long argument)
{
    int status;
    struct user_regs_struct original_regs;

    // Save original registers
    // print err here because this isn't specific enough.
    if (ptrace(PTRACE_GETREGS, pid, NULL, &original_regs) == -1)
    {
        error_exit("Failed to get original registers");
    }

    printf("Original RIP: 0x%llx\n", original_regs.rip);
    printf("Target function address: 0x%lx\n", func_addr);

    // Set up the function call
    struct user_regs_struct regs = original_regs;
    regs.rip = func_addr; // Set instruction pointer to function address
    regs.rdi = argument;  // First argument in x86_64 calling convention

    // Align stack
    regs.rsp = (regs.rsp - 128) & ~0xf;

    // Set up a return address that will cause a trap
    unsigned long trap_addr = 0xdeadbeef;
    if (ptrace(PTRACE_POKEDATA, pid, regs.rsp, trap_addr) == -1)
    {
        error_exit("Failed to write return address");
    }

    // Set the new registers
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
    {
        error_exit("Failed to set registers");
    }

    // Continue execution
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
    {
        error_exit("Failed to continue execution");
    }

    // Wait for the function to complete (will trap on invalid return address)
    waitpid(pid, &status, 0);

    if (!WIFSTOPPED(status))
    {
        fprintf(stderr, "Child process did not stop as expected\n");
        return -1;
    }

    // Get the return value
    struct user_regs_struct final_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &final_regs) == -1)
    {
        error_exit("Failed to get final registers");
    }

    printf("Final RIP: 0x%llx\n", final_regs.rip);
    printf("Return value (RAX): %lld\n", final_regs.rax);

    // Restore original registers
    if (ptrace(PTRACE_SETREGS, pid, NULL, &original_regs) == -1)
    {
        error_exit("Failed to restore original registers");
    }

    return final_regs.rax;
}

int main(int argc, char *argv[])
{
    pid_t pid;
    int status;
    unsigned long target_function_addr = 0;

    // Check arguments
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <path_to_target>\n", argv[0]);
        exit(1);
    }

    // Fork a child process
    pid = fork();
    if (pid < 0)
    {
        error_exit("Failed to fork");
    }

    if (pid == 0)
    {
        /* Child process; this is the target */

        // Set up tracing - PTRACE_TRACEME should be the flag that allows parent to trace.
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
        {
            error_exit("Child: ptrace TRACEME failed");
        }

        // Put the child in its own process group
        // I ripped this from the shell code I wrote a long time ago, as I believe it was good practice.
        if (setpgid(0, 0) < 0)
        {
            error_exit("Child: setpgid failed");
        }

        // Stop the process so the parent can set up tracing
        // before we exec the target
        raise(SIGSTOP);

        // Execute the target program
        execl(argv[1], argv[1], NULL);

        // Should not reach here unless exec fails... right??
        error_exit("Child: execl failed");
    }
    else
    {
        /* Parent process - this is the tracer */
        printf("Child process started with PID: %d\n", pid);

        // Wait for the child to stop itself with SIGSTOP
        waitpid(pid, &status, 0);
        if (!WIFSTOPPED(status))
        {
            error_exit("Child did not stop as expected");
        }

        // Set ptrace options. I think I got these right, but honestly who knows.
        if (ptrace(PTRACE_SETOPTIONS, pid, 0,
                   PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC) < 0)
        {
            error_exit("Failed to set ptrace options");
        }

        // Continue the child's execution
        if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0)
        {
            error_exit("Failed to continue child process");
        }

        // Wait for child to stop at execve
        waitpid(pid, &status, 0);
        if (!WIFSTOPPED(status))
        {
            error_exit("Child did not stop at execve");
        }

        printf("Child has exec'd the target program\n");

        /* NEW STUFF THAT MIGHT SUCK */
        // It seems like main in the target was executing too quickly for me to actually call
        // the target function in the child. So the goal here is to make sure we stop this in main.

        // Find the address of main in the target process, similar to how I do for target function
        unsigned long main_addr = 0;
        char main_cmd[256];
        sprintf(main_cmd, "nm %s | grep ' T main$' | cut -d ' ' -f 1", argv[1]);
        printf("Running command to find main: %s\n", main_cmd);

        FILE *main_fp = popen(main_cmd, "r");
        if (main_fp == NULL)
        {
            error_exit("Failed to run nm command for main");
        }

        char main_hex_addr[20] = {0};
        if (fgets(main_hex_addr, sizeof(main_hex_addr), main_fp) != NULL)
        {
            main_addr = strtoul(main_hex_addr, NULL, 16);
            printf("Found main at offset 0x%lx\n", main_addr);
        }
        else
        {
            pclose(main_fp);
            error_exit("Failed to find main address");
        }
        pclose(main_fp);

        // Read the original instruction at main
        long original_instruction = ptrace(PTRACE_PEEKTEXT, pid, main_addr, NULL);
        if (original_instruction == -1 && errno != 0)
        {
            error_exit("Failed to read instruction at main");
        }
        printf("Original instruction at main: 0x%lx\n", original_instruction);

        // Replace the first byte with INT3 (0xCC) to create a breakpoint
        /* QUESTION: is this the best way to do this? This is my first time intentionally */
        /* creating a break point in code. */
        long breakpoint_instruction = (original_instruction & ~0xFF) | 0xCC;
        if (ptrace(PTRACE_POKETEXT, pid, main_addr, breakpoint_instruction) == -1)
        {
            error_exit("Failed to set breakpoint at main");
        }
        printf("Breakpoint set at main (0x%lx)\n", main_addr);

        // Continue the child's execution, it should now stop at the breakpoint
        if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0)
        {
            error_exit("Failed to continue child process");
        }

        // Wait for child to hit the breakpoint
        waitpid(pid, &status, 0);

        if (WIFEXITED(status))
        {
            printf("Child has EXITED with status %d\n", WEXITSTATUS(status));
            exit(1);
        }
        else if (WIFSTOPPED(status))
        {
            printf("Child has stopped with signal %d\n", WSTOPSIG(status));

            // Check if it stopped due to our breakpoint (SIGTRAP), which it better have.
            if (WSTOPSIG(status) == SIGTRAP)
            {
                printf("Breakpoint hit at main\n");

                // Get the current registers
                // NOTE: I am stil using user_regs_struct after our discussion last week.
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
                {
                    error_exit("Failed to get registers at breakpoint");
                }

                // Back up the instruction pointer to the breakpoint address
                // RIP will be pointing to the next instruction after the breakpoint
                regs.rip = main_addr;

                // Restore the original instruction
                if (ptrace(PTRACE_POKETEXT, pid, main_addr, original_instruction) == -1)
                {
                    error_exit("Failed to restore original instruction");
                }

                // Update registers to reset the instruction pointer
                if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
                {
                    error_exit("Failed to reset instruction pointer");
                }

                printf("Restored original instruction at main and reset RIP\n");
            }
            else
            {
                printf("Child stopped, but not at our breakpoint\n");
            }
        }
        else
        {
            printf("Unexpected status change: %d\n", status);
            exit(1);
        }

        printf("Child has stopped at main. Getting target_function address...\n");

        /* END NEW STUFF THAT MIGHT SUCK */

        // // Let the child run and stop at main
        // if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0)
        // {
        //     error_exit("Failed to continue child process");
        // }

        // // Wait for the child to reach main
        // waitpid(pid, &status, 0);

        // if (WIFEXITED(status))
        // {
        //     printf("Child has EXITED with status %d\n", WEXITSTATUS(status));
        //     exit(1);
        // }
        // else if (WIFSTOPPED(status))
        // {
        //     printf("Child has stopped with signal %d\n", WSTOPSIG(status));
        // }
        // else
        // {
        //     printf("Unexpected status change: %d\n", status);
        //     exit(1);
        // }

        printf("Child has stopped. Getting target_function address...\n");

        // Get the process's memory map to find target_function
        char maps_path[64];
        sprintf(maps_path, "/proc/%d/maps", pid);
        printf("Reading memory map from: %s\n", maps_path);

        // Get target_function offset using readelf or nm on the binary
        char cmd[256];
        sprintf(cmd, "nm -D %s | grep 'target_function$' | cut -d ' ' -f 1", argv[1]);
        printf("Running command: %s\n", cmd);

        FILE *fp = popen(cmd, "r");
        if (fp == NULL)
        {
            error_exit("Failed to run nm command");
        }

        char hex_addr[20] = {0};
        if (fgets(hex_addr, sizeof(hex_addr), fp) != NULL)
        {
            target_function_addr = strtoul(hex_addr, NULL, 16);
            printf("Found target_function at offset 0x%lx\n", target_function_addr);
        }
        else
        {
            // Try alternate approach - look for T symbol
            pclose(fp);
            sprintf(cmd, "nm %s | grep ' T target_function$' | cut -d ' ' -f 1", argv[1]);
            fp = popen(cmd, "r");
            if (fp == NULL)
            {
                error_exit("Failed to run alternate nm command");
            }

            if (fgets(hex_addr, sizeof(hex_addr), fp) != NULL)
            {
                target_function_addr = strtoul(hex_addr, NULL, 16);
                printf("Found target_function at offset 0x%lx\n", target_function_addr);
            }
            else
            {
                pclose(fp);
                error_exit("Failed to find target_function address");
            }
        }
        pclose(fp);

        // Call the target function with argument 42
        printf("Calling target_function(42)...\n");
        int result = call_function(pid, target_function_addr, 42);
        printf("Function returned: %d\n", result);

        // Let the child continue until completion
        if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
        {
            error_exit("Failed to continue child process");
        }

        // Wait for child to terminate
        waitpid(pid, &status, 0);

        if (WIFEXITED(status))
        {
            printf("Child exited with status %d\n", WEXITSTATUS(status));
        }
        else if (WIFSIGNALED(status))
        {
            printf("Child terminated by signal %d\n", WTERMSIG(status));
        }
    }

    return 0;
}