#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

int main() {
    const char *file_name = "/tmp/file";
    int pipe_fd = -1;
    int data_fd = -1;
    int res = 0;
    const int open_mode = O_WRONLY|O_NONBLOCK;
    int bytes_sent = 0;
    char buf[PIPE_BUF*2];
    
    char *key = "/home/caros/secure/otawebsrv.key";
    int key_fd = open(key, O_RDONLY);
    int byte_read = 0;

    printf("PIPE_BUF is %d\n", PIPE_BUF);

    if (access(file_name, F_OK) == -1) {
        printf("mkfilo\n");
        res = mkfifo(file_name, 0777);
        if (res != 0) {
            printf("mkfifo failed\n");
            return -1;
        }
    }

    printf("open filo\n");
    pipe_fd = open(file_name, open_mode);
    if (-1 == pipe_fd) {
        printf("open fifo failed, %d %s\n", errno, strerror(errno));
        return -1;
    }
    byte_read =  read(key_fd, buf, PIPE_BUF*2);
    buf[byte_read] = '\0';
    while (byte_read > 0) {
        printf("write fifo\n");
        res = write(pipe_fd, buf, byte_read);
        if (res == -1) {
            printf("write failed\n");
            close(pipe_fd);
            return -1;
        }
        byte_read = read(key_fd, buf, PIPE_BUF*2);
        buf[byte_read] = '\0';
    }
    close(pipe_fd);
    return 0;
}

