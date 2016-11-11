// This utility changes the owner of a directory and all of its contents
// It works on Linux and it expects to have the setuid bit or an equivalent:
//
// $ sudo chown root chown-nosudo
// $ sudo chmod 4755 chown-nosudo
//
// or:
//
// $ sudo chown root chown-nosudo
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
#   define LOG
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


int is_allowed(const struct stat* st) {
    // check mode against the blacklist
    int i, mode;

    mode = st->st_mode & S_IFMT;
    for (i = 0; i < BLACKLIST_STAT_SIZE; ++i) {
        if (mode == BLACKLIST_STAT[i]) {
            return 0;
        }
    }
    // check if it has hardlinks
    if (mode == S_IFREG && st->st_nlink > 1) {
        return 0;
    }
    return 1;
}

int iterate_dir(const char* path, iterate_fn fn) {
    int result = 0;
    struct dirent* dp = NULL;
    DIR* dfd = NULL;
    struct stat stbuf = {0};
    char pathbuf[1024] = {0};
    unsigned int i = 0;

    if ((dfd = opendir(path)) == NULL) {
        LOG("%s: unable to open dir\n", path);
        result = 1;
        goto cleanup;
    }
    while (dp = readdir(dfd)) {
        // skip . and ..
        if (!dp->d_name || !strcmp(dp->d_name, ".") || !strcmp(dp->d_name, "..")) {
            continue;
        }
        snprintf(pathbuf, sizeof(pathbuf), "%s/%s", path, dp->d_name);
        if (lstat(pathbuf, &stbuf) == -1) {
            LOG("%s: unable to stat file\n", pathbuf);
            continue;
        }
        // security checks
        if (!is_allowed(&stbuf)) {
            LOG("%s: skipping for security reasons, stat = %#o, nlink = %d\n",
                pathbuf, stbuf.st_mode, stbuf.st_nlink);
            continue;
        }
        // apply the operation
        fn(pathbuf);
        // recurse if it's a subdir
        if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
            iterate_dir(pathbuf, fn);
        }
    }

cleanup:
    if (dfd)
        closedir(dfd);
    return result;
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
    return iterate_dir(DIRECTORY, chown_path);
}
