from __future__ import absolute_import
from __future__ import print_function

import sys
import base64
import socket
import struct
import argparse
from binascii import hexlify

import nss.nss as nss
import nss.error as nss_error
import six

'''
Author: noah @thesubtlety

This program generates a pbkdf2_sha256 password hash in 389-ds Directory Server format.
Given a password and an existing password hash it will validate the password is correct.

Requirements: 
    pip install python-nss six

Example Usage:
    python 389ds-pwdcheck.py -p Password1
        389-ds password hash: {PBKDF2_SHA256}AAAIAEFB...
    python 389ds-pwdcheck.py -p Password1 --hash {PBKDF2_SHA256}AAAIAEFB...
        Correct password: Password1

Heavily based off the python-nss pbkdf2_example.py document at 
https://github.com/tiran/python-nss/blob/master/doc/examples/pbkdf2_example.py

Referenced pbkdf2_pwd.c files can be obtained from the 389-ds-base source code at
http://snapshot.debian.org/package/389-ds-base/
'''

options = None

def fmt_info(label, item, level=0, hex_data=False):
    fmt_tuples = nss.make_line_fmt_tuples(level, label+':')
    if hex_data:
        fmt_tuples.extend(nss.make_line_fmt_tuples(level+1,
                                                   nss.data_to_hex(item, 16)))
    elif isinstance(item, six.string_types):
        fmt_tuples.extend(nss.make_line_fmt_tuples(level+1, str(item)))
    else:
        fmt_tuples.extend(item.format_lines(level=level+1))
    return nss.indented_format(fmt_tuples)

def do_pbkdf2():
    # Generate a symmetric key using our data
    alg_id, sym_key = generate_key()

    # Get key data from sym_key
    '''pbkdf2_pwd.c
        if (PK11_ExtractKeyValue(symkey) == SECSuccess) {
            result = PK11_GetKeyData(symkey);
    '''    
    keydata = sym_key.key_data

    if options.verbose:
    	print(fmt_info("Key Data from sym_key", sym_key.format()))

    return keydata

def generate_key():
    # create the PBEv2 key bytes given our algos, key length, iterations, and salt
    '''pbkdf2_pwd.c
         algid = PK11_CreatePBEV2AlgorithmID(SEC_OID_PKCS5_PBKDF2, 
                                             SEC_OID_HMAC_SHA256, 
                                             SEC_OID_HMAC_SHA256,   
                                             hash_out_len, iterations, salt);
    '''
    alg_id = nss.create_pbev2_algorithm_id("SEC_OID_PKCS5_PBKDF2",
					"SEC_OID_HMAC_SHA256",
					"SEC_OID_HMAC_SHA256",
					options.key_length,
					options.iterations,
					options.salt)

    if options.verbose:
	    print(fmt_info("create_pbev2_algorithm_id returned()", alg_id))
	    print()

    # Pick a PK11 Slot to operate in (e.g. "NSS User Private Key and Certificate Services")
    '''pbkdf2_pwd.c
        static CK_MECHANISM_TYPE mechanism_array[] = {CKM_SHA256_HMAC, CKM_PKCS5_PBKD2}; // 0x00000251 and 0x000003B0, respectively
        slot = PK11_GetBestSlotMultiple(mechanism_array, 2, NULL);
        /* Gets the best slot that provides SHA256HMAC and PBKDF2 (may not be the default!) */
        Find the best slot which supports the given set of mechanisms and key sizes.
        In normal cases this should grab the first slot on the list with no fuss.
    '''
    # get_best_slot_multiple not supported in python-nss currently, but I expect it to work the same
    #slot = nss.get_internal_slot() # this works just as well
    slot = nss.get_best_slot(0x00000251) # 251 is CKM_SHA256_HMAC, get same results with 3B0
    
    # Generate the symmetric key
    '''pbkdf2_pwd.c
        symkey = PK11_PBEKeyGen(slot, algid, pwd, PR_FALSE, NULL);
    '''
    sym_key = slot.pbe_key_gen(alg_id, options.password)

    if options.verbose:
	    print(fmt_info("Using password", options.password))
	    print()
	    print(fmt_info("pbe_key_gen() returned sym_key", sym_key))
	    print()

    return alg_id, sym_key

def generate_389hash(keydata):
    # convert given iterations to 389-ds expected bytes
    '''pbkdf2_pwd.c, pbkdf2_sha256_extract function
            /* We use ntohl on this value to make sure it's correct endianess. */
            *iterations = ntohl(*iterations);
    '''
    iters = int(options.iterations)
    iterations389_bytes_for_hash = struct.pack("I", socket.htonl(iters)) 

    # debug.. useful oneliner # print("\\x" + "\\x".join(hex(ord(c))[2:] for c in bytestr))
    if options.verbose:
        print("\nHash data:")
        print(fmt_info("Iterations", str(iters), level=1))
        print(fmt_info("Iterations bytes", iterations389_bytes_for_hash, level=1, hex_data=True))
        print(fmt_info("Salt bytes", options.salt, level=1, hex_data=True))
        print(fmt_info("Key hash", keydata, level=1, hex_data=True))

    # create 389-ds pbdkf2_sha256 byte string and base64 encode it
    raw = iterations389_bytes_for_hash + options.salt + keydata
    hsh = base64.b64encode(raw)
    
    # sanity check
    assert(base64.b64decode(hsh)[0:4] == iterations389_bytes_for_hash)
    assert(base64.b64decode(hsh)[4:68] == options.salt)
    assert(base64.b64decode(hsh)[68:] == keydata)

    return hsh

def compare_hash_values(hash_389, keydata):
    # compare created key to given key
    target_pwhash389 = base64.b64decode(options.pwdhash_389)[68:]
    if target_pwhash389 != keydata:
        print("\nIncorrect password")
    else:
        print("\nCorrect password: {}\n".format(options.password))

def extract_hash_data():
    # remove {pbkdf2_sha256}
    if options.pwdhash_389[0] == "{":
        options.pwdhash_389 = options.pwdhash_389[15:]
        
    # extract the number of pbkdf2 iterations from the hash
    iterations389_bytes = base64.b64decode(options.pwdhash_389)[0:4]
    options.iterations = int(socket.htonl(struct.unpack("I",iterations389_bytes)[0]))
    assert(options.iterations < 1000000) # really? probably a copy paste error

    # extract the next 64 bytes of salt
    options.salt = base64.b64decode(options.pwdhash_389)[4:68]

def main():
    global options

    parser = argparse.ArgumentParser(description='Generate or validate 389-ds pdbkdf2-sha256 password and hash values'
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='print lots of detail')

    group = parser.add_argument_group('PBKDF2', 'Specify the PBKDF2 parameters')
    group.add_argument('--hash', dest='pwdhash_389', type=str,
                       help='389-ds formatted password hash')
    group.add_argument('-p', '--password', type=str, required=True,
                       help='password')

    if len(sys.argv) < 2:
        print(parser.print_help())
        exit(1)

    # defaults set for 389-ds pbkdf2_sha256
    parser.set_defaults(pbe_alg     = 'SEC_OID_PKCS5_PBKDF2',
                        cipher_alg  = 'SEC_OID_HMAC_SHA256',
                        prf_alg     = 'SEC_OID_HMAC_SHA256',
                        iterations  = 2048,
                        key_length  = 256,
                        salt        = bytes("A".encode('utf-8') * 64),
                        password    = 'password',
                        pwhash      = None 
                        )
    options = parser.parse_args()
    if options.verbose:
        print(options)

    # Extract the hash info if given
    if options.pwdhash_389 is not None:
        extract_hash_data()

    # Initialize NSS
    nss.nss_init_nodb()

    # Create the pbkdf2 key with the given password
    keydata = do_pbkdf2()

    # Use key data to create a 389-ds format
    hash_389 = generate_389hash(keydata)

    # either print the new hash or validate it against a given one
    if options.pwdhash_389 is None:
        print("{PBKDF2_SHA256}%s\n" % hash_389.decode("utf-8"))
    else:
        compare_hash_values(hash_389, keydata)

if __name__ == "__main__":
    sys.exit(main())
