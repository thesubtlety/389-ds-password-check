# 389-ds PBKDF2_SHA256 Password Checker

The 389ds-pwdcheck.py script compares passwords against Red Hat's 389-ds `PBKDF2_SHA256` password hashes.

## Requirements
`pip3 install python-nss`

If python-nss isn't cooperating try `apt install python-nss` or download the source files for nss and nspr and add the header files manually.
  * https://hg.mozilla.org/projects/nspr
  * https://hg.mozilla.org/projects/nss

Then
  * extract the nspr/pr/include/* files to `/usr/local/include/nspr` 
  * extract the nss/lib/* files to `/usr/local/include/nss`

## Example Usage

### Check a password against a password hash
```
~/$ python3 389ds-pwdcheck.py -p Password123 --hash {PBKDF2_SHA256}AAAnEGTxXtnR
/oox922/jZyjH6fmiIdW4AwIYZE2LfCVL/SUz5GbAHfjRj4NbN2u8ul0/j/dUzJ4gQSawGALGHZV74nOAtPttoZDTsh7BeGCLD/Ps7vRugwDdz9uPARXzF3bD/8qCpumvRGb4pehzfQsk+FnGgT
wi0rUeVaN8a7Kbv8ZpRfU2sd+208F/YL42BWAh/2tv0I4vY7ZsrCZcrUJtgKWy5Nr+t78zmPkrZsX/kgfnGdXhr50kN10cmkLQ0/cZOXo9CAkpeZyFu+wQ5vQdUaES2Vd5kBjJYPCkr4b2ocr4E
TQi3IGO2GGCoCetmMIETsudRVSxUNBbva+Vgxin5Apu4wIP/0ZyuGK6TuWLqLnNpmK3RkRx0xjqJ4nN2Ok0ul0XYBJcYIBt4UoaVM2uSa/Etw28Uy+zAsUv2AOiRo5

Correct password: Password123
```

### Compare a list of hashes against a wordlist
```
~/$ python3 389ds-pwdcheck-harness.py 389ds-pwdcheck.py guesses.txt backup.ldif.hashes 20
Loaded 1 user hashes...
Loaded 242 password to try..
username1:Password123
Elapsed time: 10.376861095428467 seconds
```

## Utility function
### Extract user:hashes from an ldif backup file
```
~/$ python ldif-to-hashes.py ./backup.ldif.example backup.ldif.hashes
username1:{PBKDF2_SHA256}AAAnEGTxXtnR/oox922/jZyjH6fmiIdW4AwIYZE2LfCVL/SUz5GbAHfjRj4NbN2u8ul0/j/dUzJ4gQSawGALGHZV74nOAtPttoZDTsh7BeGCLD/Ps7vRugwDdz9uPARXzF3bD/8qCpumvRGb4pehzfQsk+FnGgTwi0rUeVaN8a7Kbv8ZpRfU2sd+208F/YL42BWAh/2tv0I4vY7ZsrCZcrUJtgKWy5Nr+t78zmPkrZsX/kgfnGdXhr50kN10cmkLQ0/cZOXo9CAkpeZyFu+wQ5vQdUaES2Vd5kBjJYPCkr4b2ocr4ETQi3IGO2GGCoCetmMIETsudRVSxUNBbva+Vgxin5Apu4wIP/0ZyuGK6TuWLqLnNpmK3RkRx0xjqJ4nN2Ok0ul0XYBJcYIBt4UoaVM2uSa/Etw28Uy+zAsUv2AOiRo5
```

Heavily based off the python-nss pbkdf2_example.py document at
https://github.com/tiran/python-nss/blob/master/doc/examples/pbkdf2_example.py

389-ds-base source code and `pbkdf2_pwd.c` files are at
http://snapshot.debian.org/package/389-ds-base/

More details at https://www.thesubtlety.com/post/a-389-ds-pbkdf2-password-checker/

