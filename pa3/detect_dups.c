// add any other includes in the detetc_dups.h file
#include "detect_dups.h"

// define any other global variable you may need over here

// open ssl, this will be used to get the hash of the file
EVP_MD_CTX *mdctx;
const EVP_MD *EVP_md5(); // use md5 hash!!

int main(int argc, char *argv[]) {
    // perform error handling, "exit" with failure incase an error occurs

    // initialize the other global variables you have, if any

    // add the nftw handler to explore the directory
    // nftw should invoke the render_file_info function
}

// render the file information invoked by nftw
static int render_file_info(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf) {
    // perform the inode operations over here

    // invoke any function that you may need to render the file information
}

// add any other functions you may need over here