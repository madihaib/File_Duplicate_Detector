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

    if (tflag != FTW_F) return 0;            // skip everything but real files
    char *hex = getMD5(path);                // compute the MD5 hex string
    storeToTable(hex, path, sb->st_ino, sb->st_dev, (tflag == FTW_SL) ? 1 : 0); 
    free(hex);


    if (tflag == FTW_F) {
        // regular file
        char *hex = getMD5(path);
        if (hex) {
            storeToTable(hex, path, sb->st_ino, sb->st_dev, 0);
            free(hex);
        }
    }
    else if (tflag == FTW_SL) {
        // symbolic link: stat its target, but record this path as a _soft_ link
        struct stat ts;
        if (stat(path, &ts) == 0 && S_ISREG(ts.st_mode)) {
            char *hex = getMD5(path);
            if (hex) {
                storeToTable(hex, path, ts.st_ino, ts.st_dev, 1);
                free(hex);
            }
        }
    }

    return 0;



//   unsigned char* hashToCompare = (unsigned char*)malloc(md5_len * sizeof(unsigned char));
//   // fpath = my current path
//   // REMEMBER that there is no explicit loop/recurison, NFTW does it internally with its own code,
//   // DON'T NEED TO WORRY ABOUT THAT
//   printf("Inode: %lu, Name: %s", (unsigned long)sb->st_ino, path);
//   printf("\n");
//   //(unsigned long)sb->st_ino is the number of the inode
//   // fpath = my current path
//   // sb contains extra metadata about the file such as the time created, user who created, number of the inode
//   /*
//   PROBABLY NOT AS IMPORTANT:
//    //ftwbuf contains information about the base (the index in the path string where the file name starts without the parent directory and extra slashes )
//   //and level (given directory is level 0, child is 1, etc.)
//   */

//   switch (tflag)
//   {
//   case FTW_F:
//     printf(" Regular File, Last Access: %s ", ctime(&sb->st_atime));
//     hashToCompare = getMD5(path);
//     // printf("Hash IN METHOD:");
//     // for (int i=0; i<md5_len; i++)
//     // {
//     //   printf("%02x", hashToCompare[i]);
//     // }
//     printf("\n\n");
//     if (S_ISBLK(sb->st_mode))
//     {
//       printf(" (Block Device)");
//     }
//     else if (S_ISCHR(sb->st_mode))
//     {
//       printf(" (Character Device)");
//     }
//     break;
//   case FTW_D:
//     printf(" (Directory) \n");
//     printf("level=%02d, size=%07ld path=%s filename=%s\n",
//            ftwbuf->level, sb->st_size, path, path + ftwbuf->base);
//            hashToCompare = getMD5(path);
//           //  printf("Hash IN METHOD:");
//           //  for (int i=0; i<md5_len; i++)
//           //  {
//           //    printf("%02x", hashToCompare[i]);
//           //  }
//           //  printf("\n\n");
//     break;
//   case FTW_SL:
//     printf(" (Symbolic Link) \n");
//     break;
//   case FTW_NS:
//     printf(" (Unreadable) \n");
//     break;
//   case FTW_DNR:
//     printf(" (Directory cannot be read) \n");
//     break;
//   case FTW_SLN:
//     printf(" (Symbolic link refers to non-existent file)\n");
//     break;
//   default:
//     if (S_ISFIFO(sb->st_mode))
//     {
//       printf(" (FIFO)");
//     }
//     break;
//     printf("\n");
//     free(hashToCompare);
//   }

//   return 0; // DO NOT REMOVE THIS LINE.  THIS ENSURES THAT THE FILE-WALK RUNS MORE THAN ONCE.
}


// add any other functions you may need over here

char *getMD5(const char *path){

    FILE *fp = fopen(path, "rb");

    if(!fp){
        return NULL;
    }
    
    // initialize the MD5 context
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);

    char buffer[256];
    while(fscanf(fp, "%s", buffer) != EOF){
        // read the file
        EVP_DigestUpdate(mdctx, buffer, strlen(buffer)); // feed chunk of bytes
    }

    unsigned char mdValue[EVP_MAX_MD_SIZE];
    unsigned int mdValue_len;

    EVP_DigestFinal_ex(mdctx, mdValue, &mdValue_len); // gets the MD5 hash (16 bytes)

    // convert bytes to 32 char hexadecimal
    char *md5String = (char *)malloc(33);
    for(int i = 0; (unsigned)i < mdValue_len; i++){
        sprintf(md5String + i *2, "%02x", mdValue[i]);
    }
    md5String[32] = '\0';

    // close file
    fclose(fp);
    //EVP_MD_CTX_free(mdctx); // free the context
    return md5String;
}


void storeToTable(const char *md5, const char *path, ino_t inode, dev_t dev, int isSoftLink){

    // look up MD5 string in the hash table, use HASH_FIND
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


void printDuplicates(){
    /*
    File <number>:
        MD5 Hash: <MD5 hash>
        Hard Link (<reference count>): <Inode number>
            Paths: <Path 1>
                ...
                <Path N>
        Soft Link <number>(<reference count>): <Inode number>
            Paths: <Path 1>
                ...
                <Path N>
    */
    
    int fileNumber = 1;
    
    // loop through each MD5 hash
    for(hashEntry *entry = hashTable; entry != NULL; entry = entry->hh.next){
        printf("File %d:\n", fileNumber++);
        printf("\tMD5 Hash: %s\n", entry->md5);

        //count how many file nodes
        int totalFiles = 0;
        for(fileNode *file = entry->files; file != NULL; file = file->next){
            totalFiles++;
        }

        // create an array of inodes
        ino_t *inodeList = (ino_t*)malloc(totalFiles * sizeof(ino_t));
        int inodeCount = 0;

        // fill the inode list
        for(fileNode *file = entry->files; file != NULL; file = file->next){
            
            int visited = 0;
            for(int i = 0; i < inodeCount; i++){
                if(inodeList[i] == file->inode){
                    visited = 1;
                    break;
                }
            }

            if(!visited){
                inodeList[inodeCount++] = file->inode;
            }
        }

        // for each inode, print hardlinks and softlinks
        int softLinkIndex = 1;
        for(int i = 0; i < inodeCount; i++){
            ino_t inode = inodeList[i];

            // print hard links
            char **regularPaths = malloc(totalFiles * sizeof(*regularPaths));
            int hardLinkCount = 0;

            for(fileNode *file = entry->files; file != NULL; file = file->next){
                if(file->inode == inode && !file->isSoftLink){
                    regularPaths[hardLinkCount++] = file->path;
                }
            }

            printf("\t\tHard Link (%d): %lu\n", hardLinkCount, (unsigned long)inode);
            printf("\t\t\tPaths: %s\n", regularPaths[0]);

            for(int j = 1; j < hardLinkCount; j++){
                printf("\t\t\t\t%s\n", regularPaths[j]);
            }

            free(regularPaths);

            // print soft links
            char **softPaths = malloc(totalFiles * sizeof(*softPaths));
            int softLinkCount = 0;

            for(fileNode *file = entry->files; file != NULL; file = file->next){
                if(file->inode == inode && file->isSoftLink){
                    softPaths[softLinkCount++] = file->path;
                }
            }

            if(softLinkCount > 0){
                printf("\t\t\tSoft Link %d(%d): %lu\n", softLinkIndex++, softLinkCount, (unsigned long)inode);
                printf("\t\t\t\tPaths: %s\n", softPaths[0]);
                for(int j = 1; j < softLinkCount; j++){
                    printf("\t\t\t\t\t%s\n", softPaths[j]);
                }
            }
            
            free(softPaths);
        }

        free(inodeList);
        printf("\n");
    }
}


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