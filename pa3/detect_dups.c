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
ino_t arrayofInodes[100]; //global array of inodes
int leninodearray = 100;
int newlencounter = 0;
hashEntry *correctHash = NULL;
int numberofHashes = 0;
int softlinkPrintCounter = 0; //print the soft link print counter




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

void initializeArray()
{
    for (int i = 0; i<leninodearray; i++)
    {
        arrayofInodes[i] = 0;
    }
}
// void printArray()
// {
//     for (ino_t i = 0; i<leninodearray; i++)
//     {
//         printf("Element %lu: %lu\n",i, arrayofInodes[i]);
//     }
// }

void addtoArray(ino_t newinode)
{
    int isPresent = 0;
    for (int i = 0; i<leninodearray; i++)
    {
        if (arrayofInodes[i]==newinode)
        {
            isPresent = 1;
            break;
        }
    }
    if (isPresent==0)
    {
        for (int i = 0; i<leninodearray; i++)
        {
            if (arrayofInodes[i] == 0)
            {
                arrayofInodes[i] = newinode;
                break;
            }
        }
    }
}
void countElementsofNewArray()
{
    for (int i=0; i<leninodearray; i++)
    {
        if (arrayofInodes[i]!=0)
        {
            newlencounter++;
        }
    }
    // printf("New length: %d\n",newlencounter);
}


void sortArray()
{
    for (int i = 0; i<leninodearray; i++)
    {
        int temp = i;
        for (int j = 0; j<leninodearray; j++)
        {
            if ((arrayofInodes[i] < arrayofInodes[j]) && ((arrayofInodes[i]!=0) && (arrayofInodes[j]!=0)))
            {
                temp = arrayofInodes[j];
                arrayofInodes[j] = arrayofInodes[i];
                arrayofInodes[i] = temp;
            }
        }
    }
}

void countNumberofHashes()
{
    for (hashEntry *newentry = hashTable; newentry != NULL; newentry = newentry->hh.next)
    {
        numberofHashes++;
    }
}

// void fillArrayWithHashes()
// {
//     for (hashEntry *newentry = hashTable; newentry != NULL; newentry = newentry->hh.next)
//     {
//         *(hashesArray + i) = 
//     }
// }

// static int render_file_info2(const char *path, const struct stat *sb, int tflag, struct FTW *ftwbuf){
    
//     if (tflag==FTW_F)
//     {
//         printf("File Name: %s, File Type: FILE/HL, Inode: %lu\n", path, (unsigned long)sb->st_ino);
//     }
//     else if (tflag==FTW_SL)
//     {
//         printf("File Name: %s, File Type: SL, Inode: %lu\n", path, (unsigned long)sb->st_ino);
//     }
//     return 0;
// }


// render the file information invoked by nftw
static int render_file_info(const char *path, const struct stat *sb, int tflag, struct FTW *ftwbuf){

    (void)ftwbuf;
    // printf("Inode: %lu, Name: %s\n", (unsigned long)sb->st_ino, path);
    // char *hex = getMD5(path);
    // if(!hex)
    // {
    //     fprintf(stderr,"warning: could not hash %s\n", path);
    // }
    // if (tflag!=FTW_D)
    // {
    //     printf("Hash: %s\n",hex);
    //     printf("\n");
    // }
    // printf("\n");

        if(tflag == FTW_F){
            // regular file
            // printf("FILE Inode: %lu, Name: %s\n", (unsigned long)sb->st_ino, path);
            char *hex = getMD5(path);
            if(!hex){
                fprintf(stderr,"warning: could not hash %s\n", path);
                return 0;
            }
            //hex = hash
            storeToTable(hex, path, sb->st_ino, sb->st_dev, 0);
            addtoArray(sb->st_ino);
            free(hex);
        }
        else if(tflag == FTW_SL){
            //symbolic link
            //struct stat tsb;
            // if (stat(path, &tsb) == -1) {
            //     return 0;
            // }
            char *hex = getMD5(path);
            if(!hex){
                fprintf(stderr,"warning: could not hash target of %s\n", path);
                return 0;
            }
            storeToTable(hex, path, sb->st_ino, sb->st_dev, 1);
            addtoArray(sb->st_ino);
            free(hex);
            // printf("SOFT LINK Inode: %lu, Name: %s\n", (unsigned long)sb->st_ino, path);
            // store the hash in the hash table
            // storeToTable(hex, path, tsb.st_ino, tsb.st_dev, 1);
            //free(hex);
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

    //check for exising inode + dev for each file node
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

void searchHash(ino_t inode)
{
    correctHash = malloc(sizeof(hashEntry));
    for(hashEntry *newentry = hashTable; newentry != NULL; newentry = newentry->hh.next)
    {
        for (fileNode* file = newentry->files; file!=NULL; file = file->next)
        {
            if ((file->inode)==inode)
            {
                correctHash = newentry;
                break;
            }
        } 
    }
}

// void printHashes()
// {
//     for(hashEntry *newentry = hashTable; newentry != NULL; newentry = newentry->hh.next)
//     {
//         printf("MD5 Hash: %s\n",newentry->md5);
//         printf("\n");
//         for (fileNode *file = newentry->files; file != NULL; file = file->next)
//         {
//             printf("File Name: %s, File Type: FILE/HL, Inode: %lu\n", file->path, (unsigned long)file->inode);
//         }
//         printf("\n");
//     }
// }
// void printAll()
// {
//     for (hashEntry *entry = hashTable; entry!= NULL; entry = entry->hh.next)
//     {
//         printf("MD5 Hash: %s\n", entry->md5);
//         for (fileNode *file = entry->files; file != NULL; file = file->next)
//         {
//             printf("File Name: %s, File Type: FILE/HL, Inode: %lu\n", file->path, (unsigned long)file->inode);
//         }
//     }
// }
            

// void sortByInodeNumber() 
// {
//     for (hashEntry *entry = hashTable; entry!= NULL; entry = entry->hh.next)
//     {
//         fileNode *temp = malloc(sizeof(fileNode));
//         for (fileNode *file = entry->files; file != NULL; file = file->next)
//         {
//             fileNode *var = file;
//              //remember to free
//             for (fileNode *cmpFile = entry->files; cmpFile != NULL; cmpFile = cmpFile->next)
//             {
//                 if ((var->inode)<(cmpFile->inode))
//                 {
//                     //temp = var;
//                     temp->dev = var->dev;
//                     temp->inode = var->inode;
//                     temp->isSoftLink = var->isSoftLink;
//                     temp->next = var->next;
//                     temp->path = var->path;
//                     //var = cmpFile;
//                     var->dev = cmpFile->dev;
//                     var->inode = cmpFile->inode;
//                     var->isSoftLink = cmpFile->isSoftLink;
//                     var->next = cmpFile->next;
//                     var->path = cmpFile->path;
//                     // cmpFile = temp;
//                     cmpFile->dev = temp->dev;
//                     cmpFile->inode = temp->inode;
//                     cmpFile->isSoftLink = temp->isSoftLink;
//                     cmpFile->next = temp->next;
//                     cmpFile->path = temp->path;
//                 }
//             } 
//         }
//     }
// }


// void printDuplicates(){
    
//     int fileNumber = 1;
    
//     // loop through each MD5 hash
//     for(hashEntry *entry = hashTable; entry != NULL; entry = entry->hh.next){ 
//         printf("File %d:\n", fileNumber++);
//         printf("\tMD5 Hash: %s\n", entry->md5);

//         //count how many file nodes
//         int totalFiles = 0;
//         for(fileNode *file = entry->files; file != NULL; file = file->next){
//             totalFiles++;
//         }
//         printf("Total Files: %d\n", totalFiles);
//         // create an array of inodes
//         ino_t *inodeList = (ino_t*)malloc(totalFiles * sizeof(ino_t));
        
//         int inodeCount = 0;

//         // fill the inode list
//         for(fileNode *file = entry->files; file != NULL; file = file->next){
//             int visited = 0;
//             for(int i = 0; i < inodeCount; i++){
//                 if(inodeList[i] == file->inode){
//                     visited = 1;
//                     break;
//                 }
//             }
//             if(!visited){
//                 inodeList[inodeCount++] = file->inode;
//             }
//         }

//         // for each inode, print hardlinks and softlinks
//         int softLinkIndex = 1;
//         for(int i = 0; i < inodeCount; i++){
//             ino_t inode = inodeList[i];

//             // print hard links
//             char **regularPaths = malloc(totalFiles * sizeof(*regularPaths));
//             int hardLinkCount = 0;

//             for(fileNode *file = entry->files; file != NULL; file = file->next){
//                 if(file->inode == inode && !file->isSoftLink){
//                     regularPaths[hardLinkCount++] = file->path;
//                 }
//             }
//             // if (hardLinkCount !=0)
//             // {
//             printf("\t\tHard Link (%d): %lu\n", hardLinkCount, (unsigned long)inode);
//             printf("\t\t\tPaths: %s\n", regularPaths[0]);

//             for(int j = 1; j < hardLinkCount; j++){
//                 printf("\t\t\t\t%s\n", regularPaths[j]);
//             }
//             // }
//             free(regularPaths);
//             // print soft links
//             char **softPaths = malloc(totalFiles * sizeof(*softPaths));
//             int softLinkCount = 0;

//             for(fileNode *file = entry->files; file != NULL; file = file->next){
//                 if(file->inode == inode && file->isSoftLink){
//                     softPaths[softLinkCount++] = file->path;
//                 }
//             }
//             if ((softLinkCount > 0))
//             {
//                 printf("\t\t\tSoft Link %d(%d): %lu\n", softLinkIndex++, softLinkCount, (unsigned long)inode);
//                 printf("\t\t\t\tPaths: %s\n", softPaths[0]);
//                 for(int j = 1; j < softLinkCount; j++){
//                     printf("\t\t\t\t\t%s\n", softPaths[j]);
//                 }
//                 free(softPaths);
//             }
//         }
//         free(inodeList);
//         printf("\n");
//     }
// }

void printCopies()
{
    int fileNumber = 1;
    for(hashEntry *entry = hashTable; entry != NULL; entry = entry->hh.next)
    { 
        printf("File %d:\n", fileNumber++);
        printf("\tMD5 Hash: %s\n", entry->md5);
        softlinkPrintCounter = 0;
        // printf("Newlencounter: %d\n",newlencounter);
        for (int i = 0; i<newlencounter; i++) //looping through the inodes inside the inode array
        {
            // printf("I: %d\n",i);
            // printf("INODE: %ld\n",arrayofInodes[i]);
            int hardLinkCounter = 0; //checks if inode is hard link
            int softLinkCounter = 0; //checks if inode is soft link
            int isinodeHardLinkOrSoftLink = -1; //0 if hard link, 1 if soft
            searchHash(arrayofInodes[i]);
            if (correctHash!=entry)
            {
                continue;
            }
            for (fileNode *file = entry->files; file != NULL; file = file->next)
            {
                if (file->inode==arrayofInodes[i])
                {
                    if (file->isSoftLink==0) //if file is a hard link
                    {
                        isinodeHardLinkOrSoftLink = 0; //0 if hard link, 1 if soft
                        break;
                    }
                    else //file is a soft link
                    {
                        isinodeHardLinkOrSoftLink = 1;
                        break;
                    }
                }
            }
            // printf("isinode: %d\n",isinodeHardLinkOrSoftLink);
            //loop to increment the given type counter
            for(fileNode *file = entry->files; file != NULL; file = file->next)
            {
                if (isinodeHardLinkOrSoftLink==0) //hard link
                {
                    if ((file->isSoftLink == 0) && (file->inode==arrayofInodes[i]))
                    {  
                        hardLinkCounter++;
                    }
                }
                else if (isinodeHardLinkOrSoftLink==1)
                {
                    if ((file->isSoftLink == 1) && (file->inode==arrayofInodes[i]))
                    {  
                        softLinkCounter++;
                    }
                }
            }
            // printf("Hard Link Counter: %d\n",hardLinkCounter);
            // printf("Soft Link Counter: %d\n",softLinkCounter);
            //loop to print whatever type of link is current
            int k = 0; //counter variables for the loops
            // int j = 0;
            for(fileNode *file = entry->files; file != NULL; file = file->next)
            {
                if (isinodeHardLinkOrSoftLink==0)
                {
                    if ((file->isSoftLink == 0) && (file->inode==arrayofInodes[i]))
                    {
                        if (k==0)
                        {
                            printf("\t\tHard Link (%d): %lu\n", hardLinkCounter, arrayofInodes[i]);
                            printf("\t\t\tPaths: %s\n",file->path);
                        }
                        else
                        {
                            printf("\t\t\t\t %s\n",file->path);
                        }
                    k++;    
                    }
                }
            }
            k = 0;
            // j = 0;
            for(fileNode *file = entry->files; file != NULL; file = file->next)
            {
                if (isinodeHardLinkOrSoftLink==1)
                {
                    if ((file->isSoftLink == 1) && (file->inode==arrayofInodes[i]))
                    {
                        if (k==0)
                        {
                            printf("\t\tSoft Link %d(%d): %lu\n", ++softlinkPrintCounter, softLinkCounter, arrayofInodes[i]);
                            printf("\t\t\tPaths: %s\n",file->path);
                        }
                        else
                        {
                            printf("\t\t\t\t %s\n",file->path);
                        }
                        k++;
                    }
                }
                
            }
        }
    }
}
        
    //     }
    //     //array of inodes
    //     unsigned long inodeArray[hardLinkCounter];
    //     unsigned long m = 0;
    //     for(fileNode *file = entry->files; file != NULL; file = file->next)
    //     {
    //         if (file->isSoftLink == 0)
    //         {
    //             inodeArray[m] = file->inode;
    //             m++;
    //         }
    //     }
    //     for (unsigned long j = 0; j <m; j++)
    //     {
    //         for (unsigned long k = 0; k<m; k++)
    //         {
    //             if ((inodeArray[j]==inodeArray[k]) && (j!=k))
    //             {
    //                 inodeArray[k] = 0;
    //             }
    //         }
    //     }
    //     int uniqueiNodes = 0;
    //     // printf("In inode Array: \n");
    //     for (unsigned long j = 0; j < (unsigned long)hardLinkCounter; j++)
    //     {
    //         if (inodeArray[j]!=0)
    //         {
    //             uniqueiNodes++;
    //             // printf("Inode: %lu\n",inodeArray[j]);
    //         }
    //     }
    //     printf("\n");
    //     int i= 0;
    //     int j = 0;
    //     int softlinkPrintCounter = 0;
    //     //hard link printing
    //     for(fileNode *file = entry->files; file != NULL; file = file->next)
    //     {
    //         if (file->isSoftLink == 0)
    //         {
    //             if (i==0)
    //             {
    //                 printf("\t\tHard Link (%d): %lu\n", hardLinkCounter, file->inode);
    //                 printf("\t\t\tPaths: %s\n",file->path);
    //             }
    //             else
    //             {
    //                 printf("\t\t\t\t %s\n",file->path);
    //             }
    //         i++;    
    //         }
    //     }
    //     //counting soft links
    //     int softLinkCounter = 0;
    //     for(fileNode *file = entry->files; file != NULL; file = file->next)
    //     {
    //         if (file->isSoftLink == 1)
    //         {
    //             softLinkCounter++;
    //         }
    //     }
    //     i = 0;
    //     // int j = 0;
    //     for(fileNode *file = entry->files; file != NULL; file = file->next)
    //     {
    //         if (file->isSoftLink == 1)
    //         {
    //             if (i==0)
    //             {
    //                 printf("\t\tSoft Link %d(%d): %lu\n", ++softlinkPrintCounter, softLinkCounter, file->inode);
    //                 printf("\t\t\tPaths: %s\n",file->path);
    //             }
    //             else
    //             {
    //                 printf("\t\t\t\t %s\n",file->path);
    //             }
    //             i++;
    //         }
    //     }



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
        //Only for hard links
        if (nftw(argv[1], render_file_info, 20, FTW_PHYS) == -1){
        // Message in case we have the wrong directory
            fprintf(stderr, "Error <error number>: <directory> is not a valid directory\n");
            exit(EXIT_FAILURE);
        }
        //Only for soft links
        // if (nftw(argv[1], render_file_info, 20, FTW_PHYS) == -1){
        //     // Message in case we have the wrong directory
        //         fprintf(stderr, "Error <error number>: <directory> is not a valid directory\n");
        //         exit(EXIT_FAILURE);
        // }

    } else if (argv[1] == NULL){ // directory is NOT given
        fprintf(stderr, "Usage: ./detect_dups <directory>\n");
        exit(EXIT_FAILURE);
    }
    
    //printAll();
    // sortByInodeNumber();
    // printAll();
    sortArray();
    countElementsofNewArray();
    // printArray();
    printCopies();
    // printHashes();
    EVP_MD_CTX_free(mdctx); // free the context
    return 0;
}