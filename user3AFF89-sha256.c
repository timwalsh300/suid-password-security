// Compile with the following command...
// gcc user3AFF89.c -o user3AFF89.exe -I /home/user3AFF89/openssl/include -L /home/user3AFF89/openssl/lib/ -lssl -lcrypto

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/sha.h>

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
    FILE *cfg2 = fopen("/home/tw614/tw614-part2/user3AFF89.cfg", "w");
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

// Use this to generage a random string when adding a new
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

// Use this to XOR a given password with its salt before
// hashing and verifying
char *apply_salt(char *saltedPassword, char *salt, char *password)
{
    char *paddedPassword = malloc(26);
    // start with all the characters from the password
    int i;
    for (i = 0; i < strlen(password); i++) {
        paddedPassword[i] = password[i];
    }
    // pad it with 0 to match the length of the salt
    for (i = strlen(password); i < 25; i++) {
        paddedPassword[i] = '0';
    }
    paddedPassword[25] = '\0';
    for (i = 0; i < 25; i++) {
        // XOR each character of the salt and padded password in sequence
        int c = (int) salt[i] ^ (int) paddedPassword[i];
        int d = (c % 93) + 33;
        saltedPassword[i] = (char) d;
    }
    saltedPassword[25] = '\0';
    memset(paddedPassword, 0, 26);
    free(paddedPassword);
    return saltedPassword;
}

// Generate a SHA256 hash of the salted password to store in
// (and check against) the cfg file. This uses the openssl library function.
// The following StackOverflow thread was helpful for using the library...
// https://stackoverflow.com/questions/26622185/sha1-vs-shasum-from-command-line
char *get_hash(char *hashedSaltedPassword, char *saltedPassword)
{
    unsigned char *unsignedSaltedPassword = malloc(26);
    int i;
    for (i = 0; i < 26; i++) {
        unsignedSaltedPassword[i] = (unsigned char) saltedPassword[i];
    }
    unsigned char *hash = malloc(32);
    SHA256(unsignedSaltedPassword, 25, hash);
    memset(unsignedSaltedPassword, 0, 26);
    free(unsignedSaltedPassword);
    // stretch it 10,000,000 times to slow down a dictionary attack
    for (i = 0; i < 10000000; i++) {
        unsigned char *temp = malloc(32);
        int j;
        for (j = 0; j < 32; j++) {
            temp[j] = hash[j];
        }
        SHA256(temp, 32, hash);
        memset(temp, 0, 32);
        free(temp);
    }
    for(i = 0; i < 32; i++){
        // make sure we have a printable string of characters
        hashedSaltedPassword[i] = (char) ((hash[i] % 93) + 33);
    }
    hashedSaltedPassword[i] = '\0';
    memset(hash, 0, 32);
    free(hash);
    return hashedSaltedPassword;
}

// Check a username/password pair
int verify(char *username, char *password,
           char *cfg_table[20][3], int *numUsers)
{
    // Start by reading the configuration file into an array structure
    FILE *cfg = fopen("/home/tw614/tw614-part2/user3AFF89.cfg", "r");
    char *line = malloc(200);
    int row;
    int col;
    char *token;
    while ((line = fgets(line, 200, cfg)) != NULL) {
        for (col = 0; col < 3; col++) {
            cfg_table[row][col] = malloc(33);
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
    *numUsers = row;
    // iterate through the array to see if the username exists
    int i;
    for (i = 0; i < row; i++) {
        if (strcmp(cfg_table[i][0], username) == 0) {
            // now verify the provided password
            char *saltedPassword = malloc(26);
            apply_salt(saltedPassword, cfg_table[i][1], password);
            char *hashedSaltedPassword = malloc(33);
            get_hash(hashedSaltedPassword, saltedPassword);
            memset(saltedPassword, 0, 26);
            free(saltedPassword);
            if (strcmp(cfg_table[i][2], hashedSaltedPassword) == 0) {
                memset(hashedSaltedPassword, 0, 33);
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
    // make sure it's the admin
    if (strcmp(username, "admin") != 0) {
        printf("only admin can add new users!\n");
        exit(0);
    }
    // Start by asking for a password and doing verification because
    // we don't want some anonymous way to add users - the attacker
    // could just add himself and then get access to the text file
    char *password = malloc(26);
    printf("enter the password for %s: ", username);
    fgets(password, 26, stdin);
    password[strcspn(password, "\n")] = 0;
    int code = verify(username, password, cfg_table, numUsers);
    memset(password, 0, 26);
    free(password);
    if(code != 0) {
        exit(0);
    }
    // see if there is space for more users, and exit if not
    if (*numUsers == 20) {
        printf("the system is at the max number of users\n");
        exit(0);
    }
    // Now start building the new user
    char *newUser = malloc(26);
    printf("enter the new username to add (<25 characters): ");
    fgets(newUser, 26, stdin);
    newUser[strcspn(newUser, "\n")] = 0;
    // iterate through the array to see if the username exists
    int j;
    for (j = 0; j < *numUsers; j++) {
        if (strcmp(cfg_table[j][0], newUser) == 0) {
            printf("a user named %s already exists\n", newUser);
            memset(newUser, 0, 26);
            free(newUser);
            exit(0);
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
    cfg_table[*numUsers][0] = malloc(33);
    cfg_table[*numUsers][1] = malloc(33);
    cfg_table[*numUsers][2] = malloc(33);
    strcpy(cfg_table[*numUsers][0], newUser);
    char *salt = malloc(26);
    salt_shaker(salt);
    strcpy(cfg_table[*numUsers][1], salt);
    memset(salt, 0, 26);
    free(salt);
    char *saltedNewPassword = malloc(26);
    apply_salt(saltedNewPassword, cfg_table[*numUsers][1], newPassword);
    memset(newPassword, 0, 26);
    free(newPassword);
    char *hashedSaltedNewPassword = malloc(33);
    get_hash(hashedSaltedNewPassword, saltedNewPassword);
    memset(saltedNewPassword, 0, 26);
    free(saltedNewPassword);
    strcpy(cfg_table[*numUsers][2], hashedSaltedNewPassword);
    // make sure to increment numUsers before calling write_cfg, otherwise write_cfg
    // will stop before getting to the new user row in the array
    *numUsers = *numUsers + 1;
    write_cfg(cfg_table, numUsers);
    memset(hashedSaltedNewPassword, 0, 33);
    free(hashedSaltedNewPassword);
    printf("successfully added %s\n", newUser);
    FILE *log = fopen("/home/tw614/tw614-part2/user3AFF89.log", "a");
    fprintf(log, "%s added user %s\n\n", timestamp(), newUser);
    fclose(log);
    memset(newUser, 0, 26);
    free(newUser);
}

// This is the subroutine to view the contents of the text file
void read_file(char *username, char *cfg_table[20][3], int *numUsers)
{
    char *password = malloc(26);
    printf("enter the password for %s: ", username);
    fgets(password, 26, stdin);
    password[strcspn(password, "\n")] = 0;
    int code = verify(username, password, cfg_table, numUsers);
    memset(password, 0, 26);
    free(password);
    if(code != 0) {
        exit(0);
    }
    // open this only after verifying the password so that an attacker
    // can't prematurely see it in gdb or something else that looks into memory
    FILE *txt = fopen("/home/tw614/tw614-part2/user3AFF89.txt", "r");
    int c;
    while ((c = getc(txt)) != EOF) {
        printf("%c", c);
    }
    fclose(txt);
    FILE *log = fopen("/home/tw614/tw614-part2/user3AFF89.log", "a");
    fprintf(log, "%s display text for %s\n\n", timestamp(), username);
    fclose(log);
}

int main(int argc, char *argv[])
{
    char *cfg_table[20][3];
    int numUsers;

    FILE *log = fopen("/home/tw614/tw614-part2/user3AFF89.log", "a");
    fprintf(log, "%s run with arguments ", timestamp());
    int i;
    for(i = 1; i < argc; i++) {
        fprintf(log, "%s ", argv[i]);
    }
    fprintf(log, "\n\n");
    fclose(log);

    if (argc != 3) {
        printf("usage is '-a <username>' to add a user");
        printf(" or '-r <username>' to read the file\n");
        exit(0);
    } else if (strcmp(argv[1], "-a") != 0 &&
               strcmp(argv[1], "-r") != 0) {
        printf("usage is '-a <username>' to add a user");
        printf(" or '-r <username>' to read the file\n");
        exit(0);
    } else if (strcmp(argv[1], "-a") == 0) {
        add_user(argv[2], cfg_table, &numUsers);
    } else if (strcmp(argv[1], "-r") == 0) {
        read_file(argv[2], cfg_table, &numUsers);
    }
    int row;
    int col;
    for (row = 0; row < numUsers; row++) {
        for (col = 0; col < 3; col++) {
            memset(cfg_table[row][col], 0, 33);
            free(cfg_table[row][col]);
        }
    }
}
