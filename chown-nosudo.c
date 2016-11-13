// This utility changes the owner of a directory and all of its contents recursively.
// It works on Linux and it expects to have the setuid bit or the chown cap:
//
// $ sudo chown root chown-nosudo
// $ sudo chmod 4755 chown-nosudo
//
// or:
//
// $ sudo chown root chown-nosudo
// $ sudo setcap cap_chown+ep chown-nosudo
//
// (you can use cap_chown-ep to remove it afterwards).
//
// It operates on a hardcoded directory, and it doesn't follow symlinks,
// so it shouldn't open a big breach into your system security.

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#define DEBUG
#define DIRECTORY "/home/micheleb/Downloads"
#define OLD_UID 1170
#define OLD_GID 1000
#define NEW_UID 1000
#define NEW_GID 1000

#ifdef DEBUG
#   define LOG printf
#else
#   define LOG
#endif
#define UNUSED(x) (void)(x)

const int BLACKLIST_STAT[] = {
    S_IFSOCK,
    S_IFLNK,
    S_IFBLK,
    S_IFCHR,
    S_IFIFO,
};
const unsigned int BLACKLIST_STAT_SIZE = sizeof(BLACKLIST_STAT) / sizeof(int);

typedef int(*iterate_fn)(const char*, const struct stat* st);


int is_allowed(const struct stat* st) {
    // check mode against the blacklist
    unsigned int i;
    int mode;

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

    if ((dfd = opendir(path)) == NULL) {
        LOG("%s: unable to open dir\n", path);
        result = 1;
        goto cleanup;
    }
    while ((dp = readdir(dfd))) {
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
            LOG("%s: skipping for security reasons, stat = %#o, nlink = %lu\n",
                pathbuf, stbuf.st_mode, stbuf.st_nlink);
            continue;
        }
        // apply the operation
        if (!fn(pathbuf, &stbuf)) {
            continue;
        }
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

int print_path(const char* p, const struct stat* st) {
    UNUSED(st);
    LOG("%s\n", p);
    return 1;
}

int chown_path(const char* p, const struct stat* st) {
    int r;
    if ((st->st_uid != OLD_UID && st->st_uid != NEW_UID) ||
            (st->st_gid != OLD_GID && st->st_gid != NEW_GID)) {
        LOG("%s: unexpected uid = %#o, or gid = %#o\n", p, st->st_uid, st->st_gid);
        return 0;
    }
    if ((r = chown(p, NEW_UID, NEW_GID))) {
        LOG("%s: chown failed with errno %d\n", p, r);
    }
    return 1;
}

int main() {
    return iterate_dir(DIRECTORY, chown_path);
}
