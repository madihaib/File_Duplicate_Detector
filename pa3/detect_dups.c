// add any other includes in the detetc_dups.h file
#include "detect_dups.h"
#include <ftw.h>         //this contains the NFTW function
#include <sys/stat.h>    //this contains the information needed for the stat command
#include <openssl/evp.h> //this contains the information needed for the MD5
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h> // For getuid()
#include <errno.h>
#define MAX_LEN 2048

// define any other global variable you may need over here
// const EVP_MD *MD5Type = NULL;
// hashEntry *hashTable = NULL;
unsigned int md5_len = 0;
// add the nftw handler to explore the directory
// nftw should invoke the render_file_info function
int compute_file_hash(const char *path, EVP_MD_CTX *mdctx, unsigned char *md_value,
                      unsigned int *md5_len)
{
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

char* getMD5(const char *filename)
{
  int j;
  unsigned char md5_value[EVP_MAX_MD_SIZE];
  unsigned char* hashaspointer = (unsigned char*)malloc(EVP_MAX_MD_SIZE * sizeof(unsigned char));
  int err;
  EVP_MD_CTX *mdctx;
  mdctx = EVP_MD_CTX_new();
  if (!mdctx)
  {
    fprintf(stderr, "%s::%d::Error allocating MD5 context %d\n", __func__,
            __LINE__, errno);
    exit(EXIT_FAILURE);
  }
  err = compute_file_hash(filename, mdctx, md5_value, &md5_len);
  if (err < 0)
  {
    fprintf(stderr, "error computing hash");
  }
  printf("Hash here: \n");
  for (int i = 0; i < md5_len; i++)
  {
    printf("%02x", md5_value[i]);
    hashaspointer[i] = md5_value[i];
  }
  printf("\n");
  EVP_MD_CTX_free(mdctx); 
  return hashaspointer;
}

// render the file information invoked by nftw
static int render_file_info(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
  unsigned char* hashToCompare = (unsigned char*)malloc(md5_len * sizeof(unsigned char));
  // fpath = my current path
  // REMEMBER that there is no explicit loop/recurison, NFTW does it internally with its own code,
  // DON'T NEED TO WORRY ABOUT THAT
  printf("Inode: %lu, Name: %s", (unsigned long)sb->st_ino, fpath);
  printf("\n");
  //(unsigned long)sb->st_ino is the number of the inode
  // fpath = my current path
  // sb contains extra metadata about the file such as the time created, user who created, number of the inode
  /*
  PROBABLY NOT AS IMPORTANT:
   //ftwbuf contains information about the base (the index in the path string where the file name starts without the parent directory and extra slashes )
  //and level (given directory is level 0, child is 1, etc.)
  */

  switch (tflag)
  {
  case FTW_F:
    printf(" Regular File, Last Access: %s ", ctime(&sb->st_atime));
    hashToCompare = getMD5(fpath);
    // printf("Hash IN METHOD:");
    // for (int i=0; i<md5_len; i++)
    // {
    //   printf("%02x", hashToCompare[i]);
    // }
    printf("\n\n");
    if (S_ISBLK(sb->st_mode))
    {
      printf(" (Block Device)");
    }
    else if (S_ISCHR(sb->st_mode))
    {
      printf(" (Character Device)");
    }
    break;
  case FTW_D:
    printf(" (Directory) \n");
    printf("level=%02d, size=%07ld path=%s filename=%s\n",
           ftwbuf->level, sb->st_size, fpath, fpath + ftwbuf->base);
           hashToCompare = getMD5(fpath);
           printf("Hash IN METHOD:");
           for (int i=0; i<md5_len; i++)
           {
             printf("%02x", hashToCompare[i]);
           }
           printf("\n\n");
    break;
  case FTW_SL:
    printf(" (Symbolic Link) \n");
    break;
  case FTW_NS:
    printf(" (Unreadable) \n");
    break;
  case FTW_DNR:
    printf(" (Directory cannot be read) \n");
    break;
  case FTW_SLN:
    printf(" (Symbolic link refers to non-existent file)\n");
    break;
  default:
    if (S_ISFIFO(sb->st_mode))
    {
      printf(" (FIFO)");
    }
    break;
    printf("\n");
    free(hashToCompare);
  }

  return 0; // DO NOT REMOVE THIS LINE.  THIS ENSURES THAT THE FILE-WALK RUNS MORE THAN ONCE.
}

int main(int argc, char *argv[])
{
  // If argument was not passed
  if ((argv[1] != NULL) && (argc == 2))
  {
    char *path = argv[1];
    // Calling nftw

    if (nftw(argv[1], render_file_info, 20, 0) == -1)
    {
      // Message in case we have the wrong directory
      fprintf(stderr, "Error <error number>: <directory> is not a valid directory\n");
      exit(EXIT_FAILURE);
    }
  }
  // directory is NOT given
  else if (argv[1] == NULL)
  {
    fprintf(stderr, "Usage: ./detect_dups <directory>\n");
    exit(EXIT_FAILURE);
  }
  return 0;
}
