# suid-password-security

This was a small academic exercise to learn about Linux SUID security and about proper handling and storage of passwords. The premise is that the compiled executable should have SUID privileges to 
open the .txt file of the same name which is only readable by the program's owner. The .cfg file serves as password storage and is writable only for the program's owner. An attacker should be able to 
examine or copy the source code and .cfg file and execute any code they choose in their own environment, and still not get access to the secret .txt file contents. I show two versions: one called 
userD41D5.c that uses scrypt as the key-derivation/hash function, and another called user3AFF89-sha256.c that uses many rounds of SHA256 for slow hashing of passwords. You must obtain the libscrypt or 
openssl libraries separately.
