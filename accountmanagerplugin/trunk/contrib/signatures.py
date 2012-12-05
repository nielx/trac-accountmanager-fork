#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Steffen Hoffmann
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#  3. The name of the author may not be used to endorse or promote
#     products derived from this software without specific prior
#     written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
import sys

try:
    from hashlib import md5, sha1
except ImportError:
    import md5
    md5 = md5.new
    import sha
    sha1 = sha.new


def walktree(top, filter):
    files = []
    for items in os.walk('.'):
        if len(items[2]) < 1:
            # Skip empty directories.
            continue
        for filename in items[2]:
            path = ''.join([top, items[0].lstrip('.'), '/', filename])
            if not path in filter:
                files.append(path)
    return files

def _open(path, mode='rb'):
    f = None
    if not 'w' in mode and not os.path.exists(path):
        print('Can\'t locate "%s"' % path)
    else:
        try:
            f = open(path, mode)
        except:
            print('Can\'t read "%s"' % path)
            pass
    return f

def sign(action='r'):
    filter = []
    passed = True
    top = os.path.abspath('.')
    if action in ['r', 'w']:
        md5sums = _open(''.join([top, '/', 'acct_mgr-md5sums']), action)
        if md5sums:
            # Skip recursive operation on hash files.
            filter.append(md5sums.name)
        sha1sums = _open(''.join([top, '/', 'acct_mgr-sha1sums']), action)
        if sha1sums:
            filter.append(sha1sums.name)
    else:
        print('Error: Unsupported operation "%s".' % action)
        return
    hashes = {}
    for path in walktree(top, filter):
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
                sum, path = line.strip(' \n').split(' ')
                if not path in hashes.keys():
                    print('md5: "%s" missing' % path)
                    passed = False
                elif not hashes[path].pop('md5') == sum:
                    print('md5: "%s" changed' % path)
                    passed = False
        if sha1sums:
            for line in sha1sums.readlines():
                sum, path = line.strip(' \n').split(' ')
                if not path in hashes.keys():
                    print('sha1: "%s" missing' % path)
                    passed = False
                elif not hashes[path].pop('sha1') == sum:
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
        for path in hashes.keys():
            md5sums.write(''.join([hashes[path]['md5'], ' ', path, '\n']))
            sha1sums.write(''.join([hashes[path]['sha1'], ' ', path, '\n']))
    # DEVEL: Better use new 'finally' statement here, but
    #   still need to care for Python 2.4 (RHEL5.x) for now
    if isinstance(f, file):
        f.close()
    for f in [md5sums, sha1sums]:
        if isinstance(f, file):
            f.close()
    if action == 'r' and md5sums and sha1sums and passed == True:
        print('Check passed.')

if __name__ == '__main__':
    if len(sys.argv) > 1:
        sign(sys.argv[1])
    else:
        sign()

