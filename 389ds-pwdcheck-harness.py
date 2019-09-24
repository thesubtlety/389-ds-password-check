#!/bin/env python
import os
import sys
import time
import shlex
import random
import traceback
import subprocess
from queue import Queue
from threading import Thread, Lock

# inefficient basic multi threaded password checker

guess_q = Queue()
ds389check_file = ""

def check_hash(user, uhash):
    r = pwdict.copy()
    random.shuffle(r)
    for guess in r:
        cmd = 'python3 {} -p {} --hash {}'.format(ds389check_file, shlex.quote(guess), shlex.quote(uhash))
        args = shlex.split(cmd)
        p = subprocess.Popen(args, stdout=subprocess.PIPE)
        r, errs = p.communicate()
        if b"Correct password" in r:
            print("%s:%s" % (user,guess))
            return

def guess_worker():
    while True:
        user, uhash = guess_q.get()
        try:
            check_hash(user, uhash)
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
        guess_q.task_done()

def main():
    global hashes
    global pwdict
    global ds389check_file

    if len(sys.argv) < 5:
        print("Usage: {} <389ds-pwdcheck.py> <pwdict_file.txt> <target_hashes.txt> <threads>".format(sys.argv[0]))
        sys.exit(1)

    ds389check_file = sys.argv[1]
    pwdict_file = sys.argv[2]
    target_file = sys.argv[3]
    threads = int(sys.argv[4])

    start_time = time.time()
    with open(target_file) as f:
        hashes = [e.strip() for e in f.readlines() if e.strip()]
    print("Loaded {} user hashes...".format(len(hashes)))

    with open(pwdict_file, encoding="ISO-8859-1") as f:
        pwdict = [e.strip() for e in f.readlines() if e.strip()]
    print("Loaded {} password to try..".format(len(pwdict)))

    for i in range(0,threads):
        t = Thread(target=guess_worker)
        t.daemon = True
        t.start()

    for l in hashes:
        user = l.split(":")[0]
        uhash = l.split(":")[1]    
        guess_q.put((user,uhash))

    guess_q.join()
    print("Elapsed time: {} seconds".format(time.time()-start_time))

if __name__ == "__main__":
    main()
