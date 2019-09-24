#!/usr/bin/env python
import sys, ldif

# pip install python-ldap
#
# Usage: python3 ldif-to-hashes.py backup.example.ldif backup.example.hashes
#
# if you have ldapsearch output with comments, the ldif parser might complain...
# remove comments and strip down to only the user object you're interested in

def main():
    if len(sys.argv) < 2:
        print("Usage: {} <ldif_dump.ldif> <outfile>".format(sys.argv[0]))
        sys.exit(1)

    ldif_file  = sys.argv[1]
    outf = sys.argv[2]

    out = []
    with open(ldif_file, mode='r') as ldiff:
      parser = ldif.LDIFRecordList(ldiff)
      parser.parse()

    for user in parser.all_records:
      out.append({k: user[1].get(k,None) for k in ['userPassword', 'cn']})

    with open(outf,'w') as outfile:
      for each in out:
        try:
          info = each['cn'][0].decode() + ":" + each['userPassword'][0].decode()
          print(info)
          outfile.write(info + "\n")
        except Exception as e:
          #print(e)
          pass

if __name__ == "__main__":
  main()
