#ifndef SECURITY_H
#define SECURITY_H
int file_greeter();
void get_file_prt(char **port);
void get_file_url(char** url);
void get_file_key(char **shared_key);
void get_file_full(char **fullFile, int line_nmbr);
int confirm_if_file_exists();
void get_file_path(char **path);
int create_security_file(char* key, char* url, char* port);
#endif