// Compile with...
// gcc -static userD41D5.c -o userD41D5.exe -I /home/userD41D5/libscrypt -L /home/userD41D5/libscrypt -lscrypt

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <libscrypt.h>
#include <paths.h>
#include <sys/types.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#ifndef OPEN_MAX
#define OPEN_MAX 256
#endif

// This is a modified version of a nice helper function I found at
// https://stackoverflow.com/questions/9596945/how-to-get-appropriate-timestamp-in-c-for-logs
char *timestamp(void)
{
    time_t ltime;
    ltime = time(NULL);
    static char stamp[200];
    sprintf(stamp, "%s", asctime(localtime(&ltime)));
    stamp[strcspn(stamp, "\n")] = 0;
    return stamp;
}

// After making any changes to the configuration array, this writes
// those changes back to a file
void write_cfg(char *cfg_table[20][3], int *numUsers)
{
    FILE *cfg2 = fopen("/home/userD41D5/userD41D5.cfg", "w");
    int row;
    int col;
    for (row = 0; row < *numUsers; row++) {
        for (col = 0; col < 3; col++) {
            fprintf(cfg2, "%s ", cfg_table[row][col]);
        }
        fprintf(cfg2, "\n");
    }
    fclose(cfg2);
}

// Use this to generate a random string when adding a new
// user to the cfg file
char *salt_shaker(char *salt)
{
    srand(time(NULL));
    int i;
    for (i = 0; i < 25; i++) {
        // this makes sure all characters are printable so we
        // can read it and write it to the cfg file
        int c = (rand() % 93) + 33;
        salt[i] = (char) c;
    }
    salt[25] = '\0';
    return salt;
}

// Call scrypt as a key derivation function to salt and hash
// the a password in way that is very slow and memory intensive.
// http://www.tarsnap.com/scrypt.html
// Use a 3rd party library implementation of the above from
// https://github.com/technion/libscrypt
// Use the values N=2^18, r=8, p=1 to make this take a few seconds
char *get_hash(char *hashedSaltedPassword, char *salt, char *password)
{
    int i;
    uint8_t *hash = malloc(25);
    libscrypt_scrypt((const uint8_t*) password, strlen(password),
                     (const uint8_t*) salt, strlen(salt),
                     262144, 8, 1,
                     hash, 25);
    for(i = 0; i < 25; i++){
        // make sure we have a printable string of characters
        hashedSaltedPassword[i] = (char) ((hash[i] % 93) + 33);
    }
    hashedSaltedPassword[i] = '\0';
    // Use the following statement to debug or change the admin password
    // printf("%s\n", hashedSaltedPassword);
    memset(hash, 0, 25);
    free(hash);
    return hashedSaltedPassword;
}

// Authenticate a user
int verify(char *username, char *cfg_table[20][3], int *numUsers)
{
    char *password = malloc(26);
    printf("enter the password for %s: ", username);
    fgets(password, 26, stdin);
    password[strcspn(password, "\n")] = 0;

    // iterate through the array to see if the username exists
    int i;
    for (i = 0; i < *numUsers; i++) {
        if (strcmp(cfg_table[i][0], username) == 0) {
            // now verify the provided password
            char *hashedSaltedPassword = malloc(26);
            get_hash(hashedSaltedPassword,
                     cfg_table[i][1],
                     password);
            memset(password, 0, 26);
            free(password);
            if (strcmp(cfg_table[i][2], hashedSaltedPassword) == 0) {
                memset(hashedSaltedPassword, 0, 26);
                free(hashedSaltedPassword);
                return 0;
            } else {
                printf("authentication failure\n");
                return 2;
            }
        }
    }
    // username wasn't found in the .cfg table
    printf("authentication failure\n");
    return 3;
}

// This is the subroutine for adding a new user to the cfg file
void add_user(char *username, char *cfg_table[20][3], int *numUsers)
{
    // make sure it's the admin first
    if (strcmp(username, "admin") != 0) {
        printf("only admin can add new users!\n");
        exit(0);
    }

    // see if there is space for more users, and exit if not
    if (*numUsers == 20) {
        printf("the system is at the max number of users\n");
        exit(0);
    }

    // if all is OK so far, do authenticatation
    if(verify(username, cfg_table, numUsers) != 0) {
        exit(0);
    }

    // Now start building the new user
    char *newUser = malloc(26);
    // repeat this part until a good username is provided
    int goodUser = 0;
    int duplicateFound;
    while (!goodUser) {
        printf("enter the new username to add (max 25 characters): ");
        fgets(newUser, 26, stdin);
        newUser[strcspn(newUser, "\n")] = 0;
        // iterate through the array to see if the username exists
        int j;
        duplicateFound = 0;
        for (j = 0; j < *numUsers; j++) {
            if (strcmp(cfg_table[j][0], newUser) == 0) {
                printf("a user named %s already exists\n", newUser);
                duplicateFound = 1;
            }
        }
        if (!duplicateFound) {
            goodUser = 1;
        }
    }

    char *newPassword = malloc(26);
    // repeat this part until a password of at least 15 characters is provided
    int goodPassword = 0;
    while (!goodPassword) {
        printf("enter the new password for %s (15-25 characters): ", newUser);
        fgets(newPassword, 26, stdin);
        newPassword[strcspn(newPassword, "\n")] = 0;
        if (strlen(newPassword) < 15) {
            printf("your password is too short, try again\n");
        } else {
            goodPassword = 1;
        }
    }

    // Only commit changes at the end when a good password is established
    cfg_table[*numUsers][0] = malloc(26);
    cfg_table[*numUsers][1] = malloc(26);
    cfg_table[*numUsers][2] = malloc(26);
    strcpy(cfg_table[*numUsers][0], newUser);
    char *salt = malloc(26);
    salt_shaker(salt);
    strcpy(cfg_table[*numUsers][1], salt);
    memset(salt, 0, 26);
    free(salt);
    char *hashedSaltedNewPassword = malloc(26);
    get_hash(hashedSaltedNewPassword,
             cfg_table[*numUsers][1],
             newPassword);
    memset(newPassword, 0, 26);
    free(newPassword);
    strcpy(cfg_table[*numUsers][2], hashedSaltedNewPassword);
    // make sure to increment numUsers before calling write_cfg, otherwise write_cfg
    // will stop before getting to the new user row in the array
    *numUsers = *numUsers + 1;
    write_cfg(cfg_table, numUsers);
    memset(hashedSaltedNewPassword, 0, 26);
    free(hashedSaltedNewPassword);
    printf("successfully added %s\n", newUser);
    FILE *log = fopen("/home/userD41D5/userD41D5.log", "a");
    fprintf(log, "%s added user %s\n\n", timestamp(), newUser);
    fclose(log);
    memset(newUser, 0, 26);
    free(newUser);
}

// This is the subroutine to view the contents of the text file
void read_file(char *username, char *cfg_table[20][3], int *numUsers)
{
    if(verify(username, cfg_table, numUsers) != 0) {
        exit(0);
    }

    // open this only after verifying the password so that an attacker
    // can't prematurely see it in gdb or something else that looks into memory
    FILE *txt = fopen("/home/userD41D5/userD41D5.txt", "r");
    int c;
    while ((c = getc(txt)) != EOF) {
        printf("%c", c);
    }
    fclose(txt);
    FILE *log = fopen("/home/userD41D5/userD41D5.log", "a");
    fprintf(log, "%s display text for %s\n\n", timestamp(), username);
    fclose(log);
}

// from the Secure Programming Cookbook chapter 1.5
static int open_devnull(int fd)
{
  FILE *f = 0;
  if (!fd) {
      f = freopen(_PATH_DEVNULL, "rb", stdin);
  }
  else if (fd == 1) {
      f = freopen(_PATH_DEVNULL, "wb", stdout);
  }
  else if (fd == 2) {
      f = freopen(_PATH_DEVNULL, "wb", stderr);
  }
  return (f && fileno(f) == fd);
}

// also from Secure Programming Cookbook chapter 1.5
void spc_sanitize_files(void)
{
  int fd, fds;
  struct stat st;
  if ((fds = getdtablesize()) == -1) {
      fds = OPEN_MAX;
  }
  for (fd = 3; fd < fds; fd++) {
      close(fd);
  }
  for (fd = 0; fd < 3; fd++) {
    if (fstat(fd, &st) == -1 && (errno != EBADF || !open_devnull(fd))) {
        abort();
    }
  }
}

int main(int argc, char *argv[])
{
    // Start by sanitizing the environment...
    // I haven't figured out how to successfully execute attacks
    // using these yet, but glibc 2.3.5 on ia-class should be vulnerable,
    // so resetting these variables seems prudent
    setenv("LD_AUDIT", " ", 1);
    setenv("ORIGIN", " ", 1);
    // Not sure if my program could be attacked using IFS
    // either, but just to be sure, reset it now
    setenv("IFS", " \t\n", 1);
    // Per the advice of the Secure Programming Cookbook
    setenv("PATH", _PATH_STDPATH, 1);
    // And a couple others to be safe
    setenv("LD_PRELOAD", " ", 1);
    setenv("LD_LIBRARY_PATH", " ", 1);
    spc_sanitize_files();

    // Continue by appending to the log
    FILE *log = fopen("/home/userD41D5/userD41D5.log", "a");
    fprintf(log, "%s run with arguments ", timestamp());
    int i;
    for(i = 1; i < argc; i++) {
        fprintf(log, "%s ", argv[i]);
    }
    fprintf(log, "\n\n");
    fclose(log);

    // Then read the configuration file into an array structure
    char *cfg_table[20][3];
    FILE *cfg = fopen("/home/userD41D5/userD41D5.cfg", "r");
    char *line = malloc(200);
    int row = 0;
    int col;
    char *token;
    while ((line = fgets(line, 200, cfg)) != NULL) {
        for (col = 0; col < 3; col++) {
            cfg_table[row][col] = malloc(26);
            if (col == 0) {
                token = strtok(line, " ");
                token[strcspn(token, "\n")] = 0;
                strcpy(cfg_table[row][col], token);
            } else {
                token = strtok(NULL, " ");
                token[strcspn(token, "\n")] = 0;
                strcpy(cfg_table[row][col], token);
            }
        }
        row++;
    }
    free(line);
    fclose(cfg);
    int numUsers = row;

    // Now parse arguments and run the requested operation
    if (argc != 3) {
        printf("usage is '-a <username>' to add a user");
        printf(" or '-r <username>' to read the file\n");
        exit(0);
    } else if (strcmp(argv[1], "-a") != 0 &&
               strcmp(argv[1], "-r") != 0) {
        printf("usage is '-r <username>' to read the file");
        printf(" or '-a admin' to add new users\n");
        exit(0);
    } else if (strcmp(argv[1], "-a") == 0) {
        char *username = malloc(26);
        strncpy(username, argv[2], 25);
        add_user(username, cfg_table, &numUsers);
        free(username);
    } else if (strcmp(argv[1], "-r") == 0) {
        char *username = malloc(26);
        strncpy(username, argv[2], 25);
        read_file(username, cfg_table, &numUsers);
        free(username);
    }

    // Finally clean up by freeing the configuration array
    for (row = 0; row < numUsers; row++) {
        for (col = 0; col < 3; col++) {
            memset(cfg_table[row][col], 0, 26);
            free(cfg_table[row][col]);
        }
    }

    return 0;
}
