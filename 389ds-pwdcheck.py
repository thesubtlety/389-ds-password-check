#!/usr/bin/env python
# Author: noah @thesubtlety

from __future__ import absolute_import
from __future__ import print_function

import sys
import os
import base64
import socket
import struct
import argparse
import hashlib

def b64_hash_from_data(tmp_key, salt, iterations):
    iters = int(iterations)
    iterbytes = struct.pack("I", socket.htonl(iters)) 
    raw = iterbytes + salt + tmp_key
    buf = "{PBKDF2_SHA256}" + str(base64.b64encode(raw))

    if options.verbose:
        print("Iterations:\n\\x" + "\\x".join(hex(c)[2:] for c in bytearray(iterbytes)) + " (%s)" % iterations)
        print("\nSalt:\n\\x" + "\\x".join(hex(c)[2:] for c in bytearray(salt)))
        print("\nKey:\n\\x" + "\\x".join(hex(c)[2:] for c in bytearray(tmp_key)))
        print()

    return buf

def extract_hashinfo(pwdhash_389):
    if pwdhash_389[0] == "{":
        pwdhash_389 = pwdhash_389[15:]

    hash_bytes = base64.b64decode(pwdhash_389)

    iter_bytes = hash_bytes[0:4]
    iterations = int(socket.htonl(struct.unpack("I",iter_bytes)[0]))
    assert(iterations < 1000000)
    
    salt = hash_bytes[4:68]
    target_key = hash_bytes[68:]
    
    return iterations, salt, target_key

def main():
    global options
    parser = argparse.ArgumentParser(description='Check passwords against Redhat\'s 389-ds pdbkdf2_sha256 hashes')
    parser.add_argument('-v', '--verbose', action='store_true')
    group = parser.add_argument_group('password and hash arguments')
    group.add_argument('--hash', dest='password_hash', type=str, help='389-ds formatted password hash {PBKDF2_SHA256}AAnE...')
    group.add_argument('-p', '--password', type=str) 
    group.add_argument('-g', '--generate', dest='generate', help='create a 389-ds password hash')

    if len(sys.argv) < 2:
        print(parser.print_help())
        exit(1)
    
    options = parser.parse_args()

    keylen = 256
    if options.generate:
        pwd =  bytes(str(options.password).encode('utf-8'))
        salt = bytes(os.urandom(64))
        iterations = 10000
        tmp_key = hashlib.pbkdf2_hmac('sha256', pwd, salt, iterations, keylen)
        print(b64_hash_from_data(tmp_key, salt, iterations))

    else:
        pwd = bytes(str(options.password).encode('utf-8'))
        iterations, salt, target_key = extract_hashinfo(options.password_hash)
        tmp_key = hashlib.pbkdf2_hmac('sha256', pwd, bytes(salt), iterations, keylen)

        if options.verbose:
            print(b64_hash_from_data(tmp_key, salt, iterations))

        if target_key == tmp_key:
            print("\nSuccess:\n{}:{}\n".format(options.password_hash,options.password))
        else:
            print("Incorrect password\n")

if __name__ == "__main__":
    sys.exit(main())
