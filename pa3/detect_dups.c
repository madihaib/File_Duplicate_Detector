// add any other includes in the detetc_dups.h file
#include "detect_dups.h"
#include <ftw.h> //this contains the NFTW function
#include <sys/stat.h> //this contains the information needed for the stat command
#include <openssl/evp.h> //this contains the information needed for the hash
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h> // For getuid()

// define any other global variable you may need over here
const EVP_MD *MD5Type = NULL;
hashEntry *hashTable = NULL;


// open ssl, //this will be used to get the hash of the file
EVP_MD_CTX *mdctx;
const EVP_MD *EVP_md5(); // use md5 hash!!

int main(int argc, char *argv[]){

    // If argument was not passed
    if (argv[1]==NULL){
        fprintf(stderr, "Usage: ./detect_dups <directory>\n");
        //fprintf(stderr, "failure");
        exit(EXIT_FAILURE);
    }

    mdctx = EVP_MD_CTX_new();

    // If an incorrect directory was given 
    //change the NULL listing
    char *path = argv[1];
    // Calling nftw
    if (nftw(argv[1], render_file_info, 20, 0) == -1) {
        perror("nftw");
        exit(EXIT_FAILURE);
    }

    /*
    CHECKLIST: ERROR HANDLING COMPLETED
    */

    // perform error handling, "exit" with failure incase an error occurs
    // initialize the other global variables you have, if any

    // add the nftw handler to explore the directory
    // nftw should invoke the render_file_info function



    // printDuplicates();
    freeAll();
    return 0;
}

// render the file information invoked by nftw
static int render_file_info(const char *path, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{


    // perform the inode operations over here


    // invoke any function that you may need to render the file information
    char *hex = getMD5(path);
    storeToTable(hex, path, sb->st_ino, sb->st_dev);
    free(hex);
    EVP_MD_CTX_free(mdctx);
    return 0;
}

// add any other functions you may need over here

char *getMD5(const char *path){

    FILE *fp = fopen(path, "rb");

    if(fp == NULL){
        return -1;
    }
    
    // initialize the MD5 context
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
    for(int i = 0; i < mdValue_len; i++){
        sprintf(md5String + i *2, "%02x", mdValue[i]);
    }
    md5String[32] = '\0';

    // close file
    fclose(fp);
    return md5String;
}


void storeToTable(const char *md5, const char *path, ino_t inode, dev_t dev){

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
    for(fileNode *file = entry->files; file != NULL; file = file->next){
        if(file->inode == inode && file->dev == dev){
            // the file already exists, so no you just return
            return;
        }
    }
    
    // create a new file node
    fileNode *newFile = (fileNode*)malloc(sizeof(fileNode));
    newFile->path = strdup(path); // duplicate the path
    newFile->inode = inode;
    newFile->dev = dev;
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
        printf("File %d:\n", fileNumber);
        printf("\tMD5 Hash: %s\n", entry->md5);
        
        

        fileNumber++;
    }

}


void freeAll(){
    // free the hash table and all its entries
    hashEntry *currentEntry, *tmp;



}