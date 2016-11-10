#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

// everything hardcoded for better security
#define DEBUG
#define DIRECTORY "/home/micheleb/Downloads"
#define NEW_UID 1000
#define NEW_GID 1000

#ifdef DEBUG
#   define LOG printf
#else
#   define LOG (void*)
#endif

typedef void(*iterate_fn)(const char*);

int iterate_dir(const char* path, iterate_fn fn) {
    struct dirent* dp = NULL;
    DIR* dfd = NULL;
    struct stat stbuf = {0};
    char pathbuf[1024] = {0};

    if ((dfd = opendir(path)) == NULL) {
        LOG("unable to open dir %s\n", path);
        return 1;
    }
    while (dp = readdir(dfd)) {
        // skip . and ..
        if (!dp->d_name || !strcmp(dp->d_name, ".") || !strcmp(dp->d_name, "..")) {
            continue;
        }
        snprintf(pathbuf, sizeof(pathbuf), "%s/%s", path, dp->d_name);
        if (stat(pathbuf, &stbuf) == -1) {
            LOG("unable to stat file: %s\n", pathbuf);
            continue;
        }
        fn(pathbuf);
        if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
            // recurse the subdirectory
            iterate_dir(pathbuf, fn);
        }
    }
    closedir(dfd);
    return 0;
}

void print_path(const char* p) {
    LOG("%s\n", p);
}

void chown_path(const char* p) {
    int r;
    if (r = chown(p, NEW_UID, NEW_GID)) {
        LOG("chown failed with errno %d\n", r);
    }
}

int main() {
    return iterate_dir(DIRECTORY, chown_path);
}
