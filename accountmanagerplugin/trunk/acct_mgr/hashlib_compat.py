try:
    from hashlib import md5, sha1, sha512
except ImportError:
    import md5
    md5 = md5.new
    import sha
    sha1 = sha.new
    # not available before Python2.5
    sha512 = None

