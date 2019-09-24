# 389-ds PBKDF2_SHA256 Password Checker

This program generates a `pbkdf2_sha256` password hash in Red Hat's 389-ds LDAP format.
Given a password and an existing password hash it will validate the password is correct.

## Requirements:
`pip install python-nss six`

## Example Usage:
```
python 389ds-pwdcheck.py -p Password1
389-ds password hash: {PBKDF2_SHA256}AAAIAEFB...
```

```
python 389ds-pwdcheck.py -p Password1 --hash {PBKDF2_SHA256}AAAIAEFB...
Correct password: Password1
```

Heavily based off the python-nss pbkdf2_example.py document at
https://github.com/tiran/python-nss/blob/master/doc/examples/pbkdf2_example.py

Referenced pbkdf2_pwd.c files can be obtained from the 389-ds-base source code at
http://snapshot.debian.org/package/389-ds-base/

Details at https://www.thesubtlety.com/a-389-ds-pbkdf2-password-checker

'''
