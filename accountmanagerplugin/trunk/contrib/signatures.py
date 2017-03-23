#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011,2013 Steffen Hoffmann
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Steffen Hoffmann <hoff.st@web.de>

import os
import sys
from hashlib import md5, sha1


def walktree(top, filter):
    files = []
    for items in os.walk('.'):
        if len(items[2]) < 1:
            # Skip empty directories.
            continue
        for filename in items[2]:
            path = ''.join([top, items[0].lstrip('.'), '/', filename])
            if path not in filter:
                files.append(path)
    return files


def _open(path, mode='rb'):
    f = None
    if 'w' not in mode and not os.path.exists(path):
        print('Can\'t locate "%s"' % path)
    else:
        try:
            f = open(path, mode)
        except:
            print('Can\'t read "%s"' % path)
            pass
    return f


def sign(action='r'):
    filter_ = []
    passed = True
    top = os.path.abspath('.')
    if action in ['r', 'w']:
        md5sums = _open(''.join([top, '/', 'acct_mgr-md5sums']), action)
        if md5sums:
            # Skip recursive operation on hash files.
            filter_.append(md5sums.name)
        sha1sums = _open(''.join([top, '/', 'acct_mgr-sha1sums']), action)
        if sha1sums:
            filter_.append(sha1sums.name)
    else:
        print('Error: Unsupported operation "%s".' % action)
        return
    hashes = {}
    f = None
    for path in walktree(top, filter_):
        f = _open(path, 'rb')
        lines = f.readlines()
        path = path[len(top) + 1:]
        # Skip SVN support files, if present.
        if '.svn/' in path:
            continue

        hashes[path] = {}
        m = md5()
        m.update(''.join(lines))
        hashes[path]['md5'] = m.hexdigest()
        s = sha1()
        s.update(''.join(lines))
        hashes[path]['sha1'] = s.hexdigest()

    if action == 'r':
        if md5sums:
            for line in md5sums.readlines():
                sum_, path = line.strip(' \n').split(' ')
                if path not in hashes.keys():
                    print('md5: "%s" missing' % path)
                    passed = False
                elif not hashes[path].pop('md5') == sum_:
                    print('md5: "%s" changed' % path)
                    passed = False
        if sha1sums:
            for line in sha1sums.readlines():
                sum_, path = line.strip(' \n').split(' ')
                if path not in hashes.keys():
                    print('sha1: "%s" missing' % path)
                    passed = False
                elif not hashes[path].pop('sha1') == sum_:
                    print('sha1: "%s" changed' % path)
                    passed = False
        for path in hashes.keys():
            if len(hashes[path]) > 0:
                for hashtype in hashes[path].keys():
                    if (md5sums and hashtype == 'md5') or \
                            (sha1sums and hashtype == 'sha1'):
                        # This is non-fatal, but warn about it anyway.
                        print('%s: "%s" unknown (added)' % (hashtype, path))
    elif action == 'w':
        for path in sorted(hashes.keys()):
            md5sums.write(''.join([hashes[path]['md5'], ' ', path, '\n']))
            sha1sums.write(''.join([hashes[path]['sha1'], ' ', path, '\n']))
    # DEVEL: Better use new 'finally' statement here, but
    #   still need to care for Python 2.4 (RHEL5.x) for now
    if isinstance(f, file):
        f.close()
    for f in [md5sums, sha1sums]:
        if isinstance(f, file):
            f.close()
    if action == 'r' and md5sums and sha1sums and passed is True:
        print('Check passed.')


if __name__ == '__main__':
    if len(sys.argv) > 1:
        sign(sys.argv[1])
    else:
        sign()
