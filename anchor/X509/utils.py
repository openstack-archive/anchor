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


def load_pem_private_key(key_data, passwd=None):
    """Load and return an OpenSSL EVP_PKEY public key object from a data buffer

    :param key_data: The data buffer
    :param passwd: Decryption password if neded (not used for now)
    :return: an OpenSSL EVP_PKEY public key object
    """
    # TODO(tkelsey): look at using backend.read_private_key
    #

    lib = backend._lib
    ffi = backend._ffi
    data = backend._bytes_to_bio(key_data)

    evp_pkey = lib.EVP_PKEY_new()
    evp_pkey_ptr = ffi.new("EVP_PKEY**")
    evp_pkey_ptr[0] = evp_pkey
    evp_pkey = lib.PEM_read_bio_PrivateKey(data[0], evp_pkey_ptr,
                                           ffi.NULL, ffi.NULL)

    evp_pkey = ffi.gc(evp_pkey, lib.EVP_PKEY_free)
    return evp_pkey
