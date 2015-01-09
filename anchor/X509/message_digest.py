#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from cryptography.hazmat.backends.openssl import backend


class MessageDigestError(Exception):
    def __init__(self, what):
        super(MessageDigestError, self).__init__(what)


class MessageDigest(object):
    def __init__(self, algo):
        self._lib = backend._lib
        self._ffi = backend._ffi
        md = getattr(self._lib, "EVP_%s" % algo, None)
        if md is None:
            msg = 'MessageDigest error: unknown algorithm {a}'.format(a=algo)
            raise MessageDigestError(msg)

        ret = 0
        ctx = self._lib.EVP_MD_CTX_create()
        if ctx != self._ffi.NULL:
            self.ctx = ctx
            self.mda = md()
            ret = self._lib.EVP_DigestInit_ex(self.ctx,
                                              self.mda,
                                              self._ffi.NULL)

        if ret == 0:
            raise MessageDigestError("Could not setup message digest context.")

    def __del__(self):
        if getattr(self, 'ctx', None):
            self._lib.EVP_MD_CTX_cleanup(self.ctx)
            self._lib.EVP_MD_CTX_destroy(self.ctx)

    def _octx_to_num(self, x):
        v = 0L
        lx = len(x)
        for i in range(lx):
            v = v + ord(x[i]) * (256L ** (lx - i - 1))
        return v

    def update(self, data):
        ret = self._lib.EVP_DigestUpdate(self.ctx, data, len(data))
        if ret == 0:
            raise MessageDigestError("Failed to update message digest data.")

    def final(self):
        sz = self._lib.EVP_MD_size(self.mda)
        data = self._ffi.new("char[]", sz)
        ret = self._lib.EVP_DigestFinal_ex(self.ctx, data, self._ffi.NULL)
        if ret == 0:
            raise MessageDigestError("Failed to get message digest.")
        return self._ffi.string(data)
