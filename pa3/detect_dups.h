#define _XOPEN_SOURCE 500
#include <ftw.h>
/*
    Add any other includes you may need over here...
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/evp.h>
#include "uthash.h"

// define the structure required to store the file paths

typedef struct fileNode{
    char *path; // path to the file
    ino_t inode; // inode number of the file
    dev_t dev; // device number of the file
    int isSoftLink; // 1 if soft link, 0 if hard link
    struct fileNode *next; // pointer to the next file node
} fileNode;

typedef struct hashEntry {
    char md5[33]; // md5 hash of the file
    fileNode *files;
    UT_hash_handle hh; // makes this structure hashable
} hashEntry;


// process nftw files using this function
static int render_file_info(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf);

// add any other function you may need over here

char *getMD5(const char *fpath);

void storeToTable(const char *md5, const char *path, ino_t inode, dev_t dev);

void printDuplicates();

void freeAll(void);