# 389-ds PBKDF2_SHA256 Password Checker

This program generates a `pbkdf2_sha256` password hash in Red Hat's 389-ds LDAP format.
Given a password and an existing password hash it will validate the password is correct.

## Requirements:
`pip install python-nss six`

## Example Usage:
#### Generate a 389-ds pbkdf2_sha256 password hash
```
python 389ds-pwdcheck.py -p Password1
389-ds password hash: {PBKDF2_SHA256}AAAIAEFB...
```

#### Validate a password against a password hash
```
~/$ python3 389ds-pwdcheck.py -p Password123 --hash {PBKDF2_SHA256}AAAnEGTxXtnR
/oox922/jZyjH6fmiIdW4AwIYZE2LfCVL/SUz5GbAHfjRj4NbN2u8ul0/j/dUzJ4gQSawGALGHZV74nOAtPttoZDTsh7BeGCLD/Ps7vRugwDdz9uPARXzF3bD/8qCpumvRGb4pehzfQsk+FnGgT
wi0rUeVaN8a7Kbv8ZpRfU2sd+208F/YL42BWAh/2tv0I4vY7ZsrCZcrUJtgKWy5Nr+t78zmPkrZsX/kgfnGdXhr50kN10cmkLQ0/cZOXo9CAkpeZyFu+wQ5vQdUaES2Vd5kBjJYPCkr4b2ocr4E
TQi3IGO2GGCoCetmMIETsudRVSxUNBbva+Vgxin5Apu4wIP/0ZyuGK6TuWLqLnNpmK3RkRx0xjqJ4nN2Ok0ul0XYBJcYIBt4UoaVM2uSa/Etw28Uy+zAsUv2AOiRo5

Correct password: Password123
```

#### Extract user:hashes from an ldif backup file
```
~/$ python ldif-to-hashes.py ./backup.ldif.example backup.ldif.hashes
username1:{PBKDF2_SHA256}AAAnEGTxXtnR/oox922/jZyjH6fmiIdW4AwIYZE2LfCVL/SUz5GbAHfjRj4NbN2u8ul0/j/dUzJ4gQSawGALGHZV74nOAtPttoZDTsh7BeGCLD/Ps7vRugwDdz9uPARXzF3bD/8qCpumvRGb4pehzfQsk+FnGgTwi0rUeVaN8a7Kbv8ZpRfU2sd+208F/YL42BWAh/2tv0I4vY7ZsrCZcrUJtgKWy5Nr+t78zmPkrZsX/kgfnGdXhr50kN10cmkLQ0/cZOXo9CAkpeZyFu+wQ5vQdUaES2Vd5kBjJYPCkr4b2ocr4ETQi3IGO2GGCoCetmMIETsudRVSxUNBbva+Vgxin5Apu4wIP/0ZyuGK6TuWLqLnNpmK3RkRx0xjqJ4nN2Ok0ul0XYBJcYIBt4UoaVM2uSa/Etw28Uy+zAsUv2AOiRo5
```

#### Compare a list of hashes against a wordlist
```
~/$ python3 389ds-pwdcheck-harness.py 389ds-pwdcheck.py guesses.txt backup.ldif.hashes 20
Loaded 1 user hashes...
Loaded 242 password to try..
username1:Password123
Elapsed time: 10.376861095428467 seconds
```

Heavily based off the python-nss pbkdf2_example.py document at
https://github.com/tiran/python-nss/blob/master/doc/examples/pbkdf2_example.py

Referenced pbkdf2_pwd.c files can be obtained from the 389-ds-base source code at
http://snapshot.debian.org/package/389-ds-base/

Details at https://www.thesubtlety.com/post/a-389-ds-pbkdf2-password-checker/

'''
