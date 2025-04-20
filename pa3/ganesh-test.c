// add any other includes in the detetc_dups.h file
#include "detect_dups.h"
#include <ftw.h> //this contains the NFTW function
#include <sys/stat.h> //this contains the information needed for the stat command
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h> // For getuid()

// define any other global variable you may need over here
const EVP_MD *MD5Type = NULL;
//hashEntry *hashTable = NULL;


// open ssl, //this will be used to get the hash of the file
EVP_MD_CTX *mdctx;
const EVP_MD *EVP_md5(); // use md5 hash!!

int main(int argc, char *argv[])
{
    // printf("argc: %d\n",argc);
    // If argument was not passed
    if (argc != 2)
    {
        fprintf(stderr, "Usage: ./detect_dups <directory>\n");
        fprintf(stderr, "failure\n");
        exit(EXIT_FAILURE);
    }
    // If an incorrect directory was given by -1
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
}

// render the file information invoked by nftw
static int render_file_info(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
    printf("Inode: %lu, Name: %s, Base: %d, Level: %d\n", (unsigned long)sb->st_ino, fpath, ftwbuf->base, ftwbuf->level);
    switch (tflag) {
        case FTW_F:
          printf(" Regular File, Last Access: %s ", ctime(&sb->st_atime));
        //   if ( S_ISBLK(sb->st_mode) ) {
        // printf(" (Block Device)");
        //   } else if ( S_ISCHR(sb->st_mode) ) {
        // printf(" (Character Device)");    
        //   }
          break;
        // case FTW_D:
        //   printf(" (Directory) \n");
        //   printf("level=%02d, size=%07ld path=%s filename=%s\n",
        //      ftwbuf->level, sb->st_size, fpath, fpath + ftwbuf->base);
        //   break; 
        // case FTW_SL:
        //   printf(" (Symbolic Link) \n");
        //   break;
        // case FTW_NS:
        //   printf(" (Unreadable) \n");
        //   break;
        // case FTW_DNR:
        //   printf(" (Directory cannot be read) \n");
        //   break;
        // case FTW_SLN:
        //   printf(" (Symbolic link refers to non-existent file)\n");
        //   break;
        // default:
        //   if (S_ISFIFO(sb->st_mode)) {
        //     printf(" (FIFO)");
        //   }
        //   break;
      }
      printf("\n");
      return 0;
    // perform the inode operations over here

    // invoke any function that you may need to render the file information
}
