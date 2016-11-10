// This utility changes the owner of a directory and all of its contents
// It works on Linux and it expects to have the setuid bit or an equivalent:
//
// $ sudo chown root chown-nosudo
// $ sudo chmod 4755 chown-nosudo
//
// or:
//
// $ sudo setcap cap_chown+ep chown-nsudo
//
// (you can use cap_chown-ep to remove it afterwards).
//
// The directory it operates is hardcoded, and it doesn't follow symlinks,
// so it shouldn't open a big breach into your system security.

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#define DEBUG
#define DIRECTORY "/home/micheleb/Downloads"
#define NEW_UID 1000
#define NEW_GID 1000

#ifdef DEBUG
#   define LOG printf
#else
#   define LOG (void*)
#endif

const int BLACKLIST_STAT[] = {
    S_IFSOCK,
    S_IFLNK,
    S_IFBLK,
    S_IFCHR,
    S_IFIFO,
};
const unsigned int BLACKLIST_STAT_SIZE = sizeof(BLACKLIST_STAT) / sizeof(int);

typedef void(*iterate_fn)(const char*);

int iterate_dir(const char* path, iterate_fn fn) {
    struct dirent* dp = NULL;
    DIR* dfd = NULL;
    struct stat stbuf = {0};
    char pathbuf[1024] = {0};
    unsigned int i = 0;
    int allowed = 1;

    if ((dfd = opendir(path)) == NULL) {
        LOG("%s: unable to open dir\n", path);
        return 1;
    }
    while (dp = readdir(dfd)) {
        // skip . and ..
        if (!dp->d_name || !strcmp(dp->d_name, ".") || !strcmp(dp->d_name, "..")) {
            continue;
        }
        snprintf(pathbuf, sizeof(pathbuf), "%s/%s", path, dp->d_name);
        if (stat(pathbuf, &stbuf) == -1) {
            LOG("%s: unable to stat file\n", pathbuf);
            continue;
        }

        // check against the blacklist
        allowed = 1;
        for (i = 0; i < BLACKLIST_STAT_SIZE; ++i) {
            if ((stbuf.st_mode & S_IFMT) == BLACKLIST_STAT[i]) {
                allowed = 0;
                break;
            }
        }
        if (!allowed) {
            LOG("%s: skipping for security reasons, stat = %d\n", pathbuf, stbuf.st_mode);
            continue;
        }
        if ((stbuf.st_mode & S_IFMT) == S_IFREG) {
            // skip hardlinks
            if (stbuf.st_nlink > 1) {
                LOG("%s: skipping hardlink (%d) for security reasons\n", pathbuf, stbuf.st_nlink);
                continue;
            }
            fn(pathbuf);
        }
        else if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
            // recurse the subdirectory
            fn(pathbuf);
            iterate_dir(pathbuf, fn);
        }
        else {
            LOG("unreachable??\n");
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
        LOG("%s: chown failed with errno %d\n", p, r);
    }
}

int main() {
    return iterate_dir(DIRECTORY, print_path);
}
