#!/usr/bin/env python
# https://github.com/deadbits
#
# download sample from malshare.com and get basic sample info.
# requires a malshare API key.
#
#
# $ python mg.py -k <malshare api key> -s a9078feebc3d689d91e1f170add899c5 --analyze
# + attempting to download sample ...
#   saved sample to /Users/aswanda/Desktop/a9078feebc3d689d91e1f170add899c5
#
#
# imphash 06aa23f14cd494d505599de2f8f8379e
# md5     a9078feebc3d689d91e1f170add899c5
# sha1    500ff94608d2e7b7303b4d293ee45a94db819411
# size    578632
# ssdeep  12288:iRefc/d1X0TM60o+F91uGcsdM4AbKG7ec/Hdch+2OsRc:iRefe0Td0Z/PDCKaeCIxi
# type    PE32 executable for MS Windows (GUI) Intel 80386 32-bit
#

import os, sys
import pefile
import hashlib
from commands import getoutput
import requests
import argparse
import ssdeep

def get_filesize(filepath):
    fin = open(filepath, 'rb')
    data = fin.read()
    fin.close()
    return len(data)

def get_imphash(filepath):
    try:
        pe = pefile.PE(filepath)
        imp = pe.get_imphash()
    except:
        return '-'
    return imp

def download(hash, api_key):
    try:
        malshare_url = 'http://api.malshare.com/sampleshare.php'
        data = {'action': 'getfile', 'api_key': api_key, 'hash': hash}
        req = requests.get(malshare_url, params=data)
    except:
        print 'error: problem making http request!'; sys.exit(1)
    if req.content == 'Sample not found':
        print 'error: sample %s not found!' % hash ; sys.exit(1)
    elif req.content == 'ERROR! => Account not activated':
        print 'error: invalid API key!'; sys.exit(1)
    else:
        if os.path.exists(hash):
            print 'error: local file ./%s already exists!' % hash; sys.exit(1)
        fout = open(hash, 'wb')
        fout.write(req.content)
        fout.close()
        print '  saved sample to %s' % (str(os.getcwd() + '/' + hash))

def get_info(filepath):
    result = {}
    result['size'] = get_filesize(filepath)
    result['md5'] = hashlib.md5(open(filepath, 'rb').read()).hexdigest()
    result['sha1'] = hashlib.sha1(open(filepath, 'rb').read()).hexdigest()
    result['imphash'] = get_imphash(filepath)
    result['ssdeep'] = ssdeep.hash_from_file(filepath)
    result['type'] = (getoutput('file %s' % filepath).split('%s: ' % filepath)[1])
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-k', '--key', help='Malshare API Key', required=True)
    parser.add_argument('-s', '--sample', help='Search / Download Hash', required=True)
    parser.add_argument('-a', '--analyze', help='Show sample info after download', action='store_true')
    args = parser.parse_args()
    api_key = args.key
    sample = args.sample

    print '+ attempting to download sample ...' % sample
    download(args.sample, api_key)

    if args.analyze:
        info = get_info(sample)
        print '\n'
        for key, value in sorted(info.iteritems()):
            print '%s\t%s' % (key, value)


