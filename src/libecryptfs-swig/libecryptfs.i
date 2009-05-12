%module libecryptfs
%{
#include "../include/ecryptfs.h"
extern binary_data ecryptfs_passphrase_blob(char *salt, char *passphrase);
extern binary_data ecryptfs_passphrase_sig_from_blob(char *blob);
extern int ecryptfs_add_blob_to_keyring(char *blob, char *sig);
%}

#include "../include/ecryptfs.h"

%typemap(out) binary_data {
    $result = PyString_FromStringAndSize((char *)($1.data),$1.size);
}

extern binary_data ecryptfs_passphrase_blob(char *salt, char *passphrase);
extern binary_data ecryptfs_passphrase_sig_from_blob(char *blob);
extern int ecryptfs_add_blob_to_keyring(char *blob, char *sig);
