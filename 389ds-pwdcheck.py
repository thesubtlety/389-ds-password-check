#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import print_function

import sys
import base64
import socket
import struct
import argparse

import nss.nss as nss
import nss.error as nss_error

pbe_alg     = "SEC_OID_PKCS5_PBKDF2"
cipher_alg  = "SEC_OID_HMAC_SHA256"
prf_alg     = "SEC_OID_HMAC_SHA256"
keylen      = 256

nss.nss_init_nodb()

def b64_hash_from_data(tmp_nss_key, salt, iterations):
    iters = int(iterations)
    iterbytes = struct.pack("I", socket.htonl(iters)) 
    raw = iterbytes + salt + tmp_nss_key
    buf = base64.b64encode(raw)

    if options.verbose:
        print("Iterations:\n\\x" + "\\x".join(hex(c)[2:] for c in bytearray(iterbytes)) + " (%s)" % iterations)
        print("\nSalt:\n\\x" + "\\x".join(hex(c)[2:] for c in bytearray(salt)))
        print("\nKey:\n\\x" + "\\x".join(hex(c)[2:] for c in bytearray(tmp_nss_key)))
        print()

    return buf

def create_pbkdf2_key(iterations, salt, pwd):
    alg_id = nss.create_pbev2_algorithm_id(pbe_alg, cipher_alg, prf_alg, keylen, iterations, salt)
    slot = nss.get_best_slot(0x00000251) # CKM_SHA256_HMAC, same results with 3B0 (CKM_PKCS5_PBKD2)
    sym_key = slot.pbe_key_gen(alg_id, pwd)

    return sym_key.key_data

def extract_hashinfo(pwdhash_389):
    if pwdhash_389[0] == "{":
        pwdhash_389 = pwdhash_389[15:]

    hash_bytes = base64.b64decode(pwdhash_389)

    iter_bytes = hash_bytes[0:4]
    iterations = int(socket.htonl(struct.unpack("I",iter_bytes)[0]))
    assert(iterations < 1000000)
    
    salt = hash_bytes[4:68]
    nss_key = hash_bytes[68:]
    
    return iterations, salt, nss_key

def main():
    global options
    parser = argparse.ArgumentParser(description='Check passwords against Redhat\'s 389-ds pdbkdf2_sha256 hashes')
    parser.add_argument('-v', '--verbose', action='store_true')
    group = parser.add_argument_group('password and hash arguments')
    group.add_argument('--hash', dest='password_hash', type=str, required=True, help='389-ds formatted password hash {PBKDF2_SHA256}AAnE...')
    group.add_argument('-p', '--password', type=str, required=True)

    if len(sys.argv) < 2:
        print(parser.print_help())
        exit(1)
    
    #password    = 'Password123'
    #password_hash = "{PBKDF2_SHA256}AAAnEGTxXtnR/oox922/jZyjH6fmiIdW4AwIYZE2LfCVL/SUz5GbAHfjRj4NbN2u8ul0/j/dUzJ4gQSawGALGHZV74nOAtPttoZDTsh7BeGCLD/Ps7vRugwDdz9uPARXzF3bD/8qCpumvRGb4pehzfQsk+FnGgTwi0rUeVaN8a7Kbv8ZpRfU2sd+208F/YL42BWAh/2tv0I4vY7ZsrCZcrUJtgKWy5Nr+t78zmPkrZsX/kgfnGdXhr50kN10cmkLQ0/cZOXo9CAkpeZyFu+wQ5vQdUaES2Vd5kBjJYPCkr4b2ocr4ETQi3IGO2GGCoCetmMIETsudRVSxUNBbva+Vgxin5Apu4wIP/0ZyuGK6TuWLqLnNpmK3RkRx0xjqJ4nN2Ok0ul0XYBJcYIBt4UoaVM2uSa/Etw28Uy+zAsUv2AOiRo5"
    options = parser.parse_args()

    iterations, salt, nss_key = extract_hashinfo(options.password_hash)
    tmp_nss_key = create_pbkdf2_key(iterations, salt, options.password)

    if options.verbose:
        b64_hash_from_data(tmp_nss_key, salt, iterations)

    if nss_key == tmp_nss_key:
        print("Correct password: {}\n".format(options.password))
    else:
        print("Incorrect password\n")

if __name__ == "__main__":
    sys.exit(main())
