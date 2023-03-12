For this project I used the openssl library and used the openssl/md5.h package

To run the project I use the following command lines:

gcc main.c lengthAttack.c -o main.exe -lcrypto
.\main.exe


/!\ /!\ /!\ /!\ /!\ /!\
When changing the messages or keys, it is necessary to keep the '\0' at the end
It can work without but just to be sure !
/!\ /!\ /!\ /!\ /!\ /!\