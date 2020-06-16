#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#define docker_prefix_size 11

//append the passed arguments into a docker run cmdline and exec it
int main(int argc, char* argv[]) {
    char* docker_prefix[] = {"docker", "run", "-a", "stdin", "-a", "stdout", "--ipc=host",
    "-v", "/sys/kernel/debug:/sys/kernel/debug:rw", "-i", "syzkaller-image"};
    char** new_args = calloc(docker_prefix_size + argc, sizeof(char*));
    memcpy(new_args, docker_prefix, docker_prefix_size*sizeof(char*));
    memcpy(new_args+docker_prefix_size, argv+1, (argc - 1) * sizeof(char*)); //no need to copy the null
    execvp("docker", new_args);
}
