/* short program to show how to use nftw call to walk the file system 
 *
 */
#define _XOPEN_SOURCE 500
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h> // For getuid()

static int print_file_info(const char *pathname, const struct stat *statbuf,
                      int typeflag, struct FTW *ftwbuf) {
  printf("Inode: %lu, Name: %s", (unsigned long)statbuf->st_ino, pathname);


  switch (typeflag) {
    case FTW_F:
      printf(" Regular File, Last Access: %s ", ctime(&statbuf->st_atime));
      if ( S_ISBLK(statbuf->st_mode) ) {
	printf(" (Block Device)");
      } else if ( S_ISCHR(statbuf->st_mode) ) {
	printf(" (Character Device)");    
      }
      break;
    case FTW_D:
      printf(" (Directory) \n");
      printf("level=%02d, size=%07ld path=%s filename=%s\n",
	     ftwbuf->level, statbuf->st_size, pathname, pathname + ftwbuf->base);
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
      if (S_ISFIFO(statbuf->st_mode)) {
        printf(" (FIFO)");
      }
      break;
  }

  // Check if the file is world-readable
  if (typeflag == FTW_F || typeflag == FTW_D) { // Only check regular files and directories
    if (statbuf->st_mode & S_IROTH) {
      // S_IROTH = 0x4 = 0000 0000 0000 0100 in binary 
      // How a mask and a value are used in an if() test in C:
      // encode state in single bits of an integer, use a constant mask and the '&' operator to see if true/false
      //   1011 0011 1101 1110   value 
      // & 0000 0000 0000 0100   mask 
      //   0000 0000 0000 0100   result
      // is the result zero? zero = false , any non zero is true 
      printf(" [WARNING: World-Readable]");
    }
  }

  printf("\n");
  return 0;
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <directory_path>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  if (nftw(argv[1], print_file_info, 20, 0) == -1) {
    perror("nftw");
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}
