// add any other includes in the detetc_dups.h file
#define _XOPEN_SOURCE 500
#include "detect_dups.h"
#include <ftw.h>         //this contains the NFTW function
#include <sys/stat.h>    //this contains the information needed for the stat command
#include <openssl/evp.h> //this contains the information needed for the MD5
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h> // For getuid()
#include <errno.h>
#include <stdbool.h>
#define MAX_LEN 2048

// define any other global variable you may need over here
const EVP_MD *MD5Type = NULL;
hashEntry *hashTable = NULL;
unsigned int md5_len = 0;

// open ssl, //this will be used to get the hash of the file
EVP_MD_CTX *mdctx;
const EVP_MD *EVP_md5(); // use md5 hash!!

// add the nftw handler to explore the directory
// nftw should invoke the render_file_info function

int compute_file_hash(const char *path, EVP_MD_CTX *mdctx, unsigned char *md_value, unsigned int *md5_len){
  
  FILE *givenFile = fopen(path, "rb"); //checks if the efile can open or NOT
  if (givenFile == NULL)
  {
    fprintf(stderr, "file does not open, try again");
  }
  char buff[MAX_LEN];
  size_t datafromstream; //this helps define the data we read from the datastream
  EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
  while ((datafromstream = fread(buff, 1, MAX_LEN, givenFile)))
  {
    EVP_DigestUpdate(mdctx, buff, datafromstream);
  }
  EVP_DigestFinal_ex(mdctx, md_value, md5_len);
  EVP_MD_CTX_reset(mdctx);
  fclose(givenFile);
  return 0;
}


// render the file information invoked by nftw
static int render_file_info(const char *path, const struct stat *sb, int tflag, struct FTW *ftwbuf){

    if(tflag == FTW_F){
        // regular file
        char *hex = getMD5(path);
        if(!hex){
            fprintf(stderr,"warning: could not hash %s\n", path);
            return 0;
        }

        storeToTable(hex, path, sb->st_ino, sb->st_dev, 0);
        free(hex);

    } else if(tflag == FTW_SL){
        // symbolic link
        struct stat tsb;
        if (stat(path, &tsb) == -1) {
            return 0;
        }

        char *hex = getMD5(path);
        if(!hex){
            fprintf(stderr,"warning: could not hash target of %s\n", path);
            return 0;
        }

        // store the hash in the hash table
        storeToTable(hex, path, tsb.st_ino, tsb.st_dev, 1);
        free(hex);
    }
    return 0;
}


char *getMD5(const char *path){

    FILE *fp = fopen(path, "rb");
    if(!fp){
        perror("Error opening file");
        return NULL;
    }
    
    unsigned char buffer[MAX_LEN];
    size_t bytesRead;
    
    // initialize a local context
    EVP_MD_CTX *local_mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(local_mdctx, EVP_md5(), NULL);
    
    // read in chunks
    while((bytesRead = fread(buffer, 1, MAX_LEN, fp)) > 0){
        EVP_DigestUpdate(local_mdctx, buffer, bytesRead);
    }
    
    unsigned char mdValue[EVP_MAX_MD_SIZE];
    unsigned int mdValue_len;
    
    EVP_DigestFinal_ex(local_mdctx, mdValue, &mdValue_len);
    
    // convert to 32 char hexadecimal
    char *md5String = (char *)malloc(33);
    for(unsigned int i = 0; i < mdValue_len; i++){
        sprintf(md5String + i * 2, "%02x", mdValue[i]);
    }

    md5String[32] = '\0';
    
    fclose(fp);
    EVP_MD_CTX_free(local_mdctx);
    return md5String;
}


void storeToTable(const char *md5, const char *path, ino_t inode, dev_t dev, int isSoftLink){

    // look up MD5 string in the hash table, use HASH_FIND_STR
    hashEntry *entry = NULL;
    HASH_FIND_STR(hashTable, md5, entry);

    // if not found, add it to the hash table
    if(entry == NULL){
        entry = (hashEntry *)malloc(sizeof(hashEntry));
        strcpy(entry->md5, md5);
        entry->files = NULL; 
        HASH_ADD_STR(hashTable, md5, entry); // add to hash table
    }

    // check for exising inode + dev for each file node
    // for(fileNode *file = entry->files; file != NULL; file = file->next){
    //     if(file->inode == inode && file->dev == dev){
    //         // the file already exists, so now you just return
    //         return;
    //     }
    // }

    // create a new file node
    fileNode *newFile = (fileNode*)malloc(sizeof(fileNode));
    newFile->path = strdup(path); // duplicate the path
    newFile->inode = inode;
    newFile->dev = dev;
    newFile->isSoftLink = isSoftLink; // 1 if soft link, 0 if hard link
    newFile->next = entry->files;
    entry->files = newFile;
}







void printDuplicates() {
    int fileNumber = 1;
    hashEntry *entry, *tmp;

    // iterate through each MD5 entry in the hash table
    HASH_ITER(hh, hashTable, entry, tmp) {
        printf("File %d\n", fileNumber++);
        printf("\tMD5 Hash: %s\n", entry->md5);

        // count hard links
        int totalHard = 0;
        for (fileNode *f = entry->files; f; f = f->next) {
            if (!f->isSoftLink) totalHard++;
        }

        // collect unique inodes
        ino_t *inodeList = malloc(totalHard * sizeof(*inodeList));
        int inodeCount = 0;
        for (fileNode *f = entry->files; f; f = f->next) {
            if (f->isSoftLink) continue;
            int seen = 0;
            for (int k = 0; k < inodeCount; k++) {
                if (inodeList[k] == f->inode) { seen = 1; break; }
            }
            if (!seen) inodeList[inodeCount++] = f->inode;
        }

        // for each inode: print hard links then soft links
        for (int i = 0; i < inodeCount; i++) {
            ino_t ino = inodeList[i];

            // --- hard links ---
            char **hardPaths = malloc(inodeCount * sizeof(*hardPaths));
            int hardCount = 0;
            for (fileNode *f = entry->files; f; f = f->next) {
                if (f->inode == ino && !f->isSoftLink) {
                    hardPaths[hardCount++] = f->path;
                }
            }
            printf("\tHard Link (%d): %lu\n", hardCount, (unsigned long)ino);
            printf("\t\tPaths: %s\n", hardPaths[0]);
            for (int j = 1; j < hardCount; j++) {
                printf("\t\t\t%s\n", hardPaths[j]);
            }
            free(hardPaths);

            // --- soft links (one block per symlink) ---
            int softIndex = 1;
            for (fileNode *f = entry->files; f; f = f->next) {
                if (f->inode == ino && f->isSoftLink) {
                    struct stat stl;
                    if (lstat(f->path, &stl) == -1) {
                        perror("lstat");
                        stl.st_ino = ino;
                    }
                    printf("\tSoft Link %d(1): %lu\n",
                           softIndex++, (unsigned long)stl.st_ino);
                    printf("\t\tPaths: %s\n", f->path);
                }
            }

            printf("\n");
        }

        free(inodeList);
    }
}









// void printDuplicates(){
    
//     int fileNumber = 1;
    
//     // loop through each MD5 hash
//     for(hashEntry *entry = hashTable; entry != NULL; entry = entry->hh.next){
//         printf("File %d:\n", fileNumber++);
//         printf("\tMD5 Hash: %s\n", entry->md5);

//     // print the file paths
//     int totalHard = 0;
//     for(fileNode *f = entry->files; f; f = f->next){
//         if(!f->isSoftLink){
//             totalHard++;
//         }
//     }

//     ino_t *inodeList = malloc(totalHard * sizeof(*inodeList));
//     int inodeCount = 0;
//     for(fileNode *f = entry->files; f; f = f->next){
//         if(f->isSoftLink){
//             continue;
//         }

//         // check if the inode is already in the list
//         int visited = 0;
//         for(int k = 0; k < inodeCount; k++){
//             if(inodeList[k] == f->inode){ 
//                 visited = 1; 
//                 break; 
//             }
//         }
//         if(!visited){
//             inodeList[inodeCount++] = f->inode;
//         }
//     }

//     // for each real inode, print its hard-links then its soft-links
//     int softIndex = 1;
//     for(int i = 0; i < inodeCount; i++){
//         ino_t ino = inodeList[i];

//         // hard links
//         char **hardPaths = malloc(inodeCount * sizeof(*hardPaths));
//         int hardCount = 0;
//         for(fileNode *f = entry->files; f; f = f->next){
//             if(f->inode == ino && !f->isSoftLink){
//                 hardPaths[hardCount++] = f->path;
//             }
//         }

//         printf("\t\tHard Link (%d): %lu\n", hardCount, (unsigned long)ino);
//         printf("\t\t\tPaths: %s\n", hardPaths[0]);

//         for(int j = 1; j < hardCount; j++){
//             printf("\t\t\t\t%s\n", hardPaths[j]);
//         }

//         free(hardPaths);

//         // soft links
//         char **softPath = malloc(inodeCount * sizeof(*softPath));
//         int softCount = 0;
//         for(fileNode *f = entry->files; f; f = f->next){
//             if(f->inode == ino && f->isSoftLink){
//                 softPath[softCount++] = f->path;
//             }
//         }

//         if(softCount){
//             // get symlink’s own inode with lstat
//             struct stat stl;

//             if(lstat(softPath[0], &stl) == -1){
//                 stl.st_ino = ino;
//             }
//             printf("\t\t\tSoft Link %d(%d): %lu\n",softIndex++, softCount, (unsigned long)stl.st_ino);
//             printf("\t\t\t\tPaths: %s\n", softPath[0]);
//             for(int j = 1; j < softCount; j++){
//                 printf("\t\t\t\t\t%s\n", softPath[j]);
//             }
//         }
//         free(softPath);
//     }

//     free(inodeList);
//     printf("\n");


//     }
// }


int main(int argc, char *argv[]){
  // If argument was not passed
    if ((argv[1] != NULL) && (argc == 2)){
    //char *path = argv[1];
    // Calling nftw

        mdctx = EVP_MD_CTX_new();
        MD5Type = EVP_md5();
        if(!mdctx || !MD5Type){
            fprintf(stderr, "Error initializing MD5 context\n");
            exit(EXIT_FAILURE);
        }

        if (nftw(argv[1], render_file_info, 20, FTW_PHYS) == -1){
        // Message in case we have the wrong directory
            fprintf(stderr, "Error <error number>: <directory> is not a valid directory\n");
            exit(EXIT_FAILURE);
        }

    } else if (argv[1] == NULL){ // directory is NOT given
        fprintf(stderr, "Usage: ./detect_dups <directory>\n");
        exit(EXIT_FAILURE);
    }
    
    printDuplicates();
    EVP_MD_CTX_free(mdctx); // free the context
    return 0;
}