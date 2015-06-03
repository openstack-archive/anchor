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

import calendar
import datetime

from cryptography.hazmat.backends.openssl import backend
import errors


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


def create_timezone(minute_offset):
    """Create a new timezone with a specified offset.

    Since tzinfo is just a base class, and tzinfo subclasses need a
    no-arguments __init__(), we need to generate a new class dynamically.

    :param minute_offset: total timezone offset in minutes
    """

    class SpecificTZ(datetime.tzinfo):
        def utcoffset(self, _dt):
            return minute_offset

        def dst(self, _dt):
            return None

        def tzname(self, _dt):
            return None

        def __repr__(self):
            sign = "+" if minute_offset > 0 else "-"
            hh = minute_offset / 60
            mm = minute_offset % 60
            return "Timezone %s%02i%02i" % (sign, hh, mm)

    return SpecificTZ()


def asn1_time_to_timestamp(t):
    """Convert from ASN1_TIME type to a UTC-based timestamp.

    :param t: ASN1_TIME to convert
    """

    gen_time = backend._lib.ASN1_TIME_to_generalizedtime(t, backend._ffi.NULL)
    if gen_time == backend._ffi.NULL:
        raise errors.ASN1TimeError("time conversion failure")

    try:
        return asn1_generalizedtime_to_timestamp(gen_time)
    finally:
        backend._lib.ASN1_GENERALIZEDTIME_free(gen_time)


def asn1_generalizedtime_to_timestamp(gt):
    """Convert from ASN1_GENERALIZEDTIME to UTC-based timestamp.

    :param gt: ASN1_GENERALIZEDTIME to convert
    """

    # ASN1_GENERALIZEDTIME is actually a string in known formats,
    # so the conversion can be done in this code
    string_time = backend._ffi.cast("ASN1_STRING*", gt)
    string_data = backend._lib.ASN1_STRING_data(string_time)
    res = backend._ffi.string(string_data)

    before_tz = res[:14]
    tz_str = res[14:]
    d = datetime.datetime.strptime(before_tz, "%Y%m%d%H%M%S")
    if tz_str == 'Z':
        # YYYYMMDDhhmmssZ
        d.replace(tzinfo=create_timezone(0))
    else:
        # YYYYMMDDhhmmss+hhmm
        # YYYYMMDDhhmmss-hhmm
        sign = -1 if tz_str[0] == '-' else 1
        hh = tz_str[1:3]
        mm = tz_str[3:5]
        minute_offset = sign * (int(mm) + int(hh) * 60)
        d.replace(tzinfo=create_timezone(minute_offset))
    return calendar.timegm(d.timetuple())


def timestamp_to_asn1_time(t):
    """Convert from UTC-based timestamp to ASN1_TIME

    :param t: time in seconds since the epoch
    """

    d = datetime.datetime.utcfromtimestamp(t)
    # use the ASN1_GENERALIZEDTIME format
    time_str = d.strftime("%Y%m%d%H%M%SZ")
    asn1_time = backend._lib.ASN1_STRING_type_new(
        backend._lib.V_ASN1_GENERALIZEDTIME)
    backend._lib.ASN1_STRING_set(asn1_time, time_str, len(time_str))
    asn1_gentime = backend._ffi.cast("ASN1_GENERALIZEDTIME*", asn1_time)
    if backend._lib.ASN1_GENERALIZEDTIME_check(asn1_gentime) == 0:
        raise errors.ASN1TimeError("timestamp not accepted by ASN1 check")

    # ASN1_GENERALIZEDTIME is a form of ASN1_TIME, so a pointer cast is valid
    return backend._ffi.cast("ASN1_TIME*", asn1_time)
