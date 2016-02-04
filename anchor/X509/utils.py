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

from __future__ import absolute_import

import calendar
import datetime
import struct

from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import netaddr
from pyasn1.type import useful as asn1_useful

from anchor.asn1 import rfc5280
from anchor.X509 import errors


def create_timezone(minute_offset):
    """Create a new timezone with a specified offset.

    Since tzinfo is just a base class, and tzinfo subclasses need a
    no-arguments __init__(), we need to generate a new class dynamically.

    :param minute_offset: total timezone offset in minutes
    """

    class SpecificTZ(datetime.tzinfo):
        def utcoffset(self, _dt):
            return datetime.timedelta(minutes=minute_offset)

        def dst(self, _dt):
            return datetime.timedelta(0)

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
    component = t.getComponent()
    timestring = component.asOctets().decode(component.encoding)
    if isinstance(component, asn1_useful.UTCTime):
        if int(timestring[0]) >= 5:
            timestring = "19" + timestring
        else:
            timestring = "20" + timestring
    return asn1_timestring_to_timestamp(timestring)


def asn1_timestring_to_timestamp(timestring):
    """Convert from ASN1_GENERALIZEDTIME to UTC-based timestamp.

    :param gt: ASN1_GENERALIZEDTIME to convert
    """

    # ASN1_GENERALIZEDTIME is actually a string in known formats,
    # so the conversion can be done in this code
    before_tz = timestring[:14]
    tz_str = timestring[14:]
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
    asn1time = rfc5280.Time()
    if d.year <= 2049:
        time_str = d.strftime("%y%m%d%H%M%SZ").encode('ascii')
        asn1time['utcTime'] = time_str
    else:
        time_str = d.strftime("%Y%m%d%H%M%SZ").encode('ascii')
        asn1time['generalTime'] = time_str
    return asn1time


# chr good for py2 and py3
_chr = chr if str is bytes else lambda x: bytes([x])


# functions needed for converting the pyasn1 signature fields
def bin_to_bytes(bits):
    """Convert bit string to byte string."""
    bits = ''.join(str(b) for b in bits)
    bits = _pad_byte(bits)
    octets = [bits[8*i:8*(i+1)] for i in range(len(bits)//8)]
    byte_list = [_chr(int(x, 2)) for x in octets]
    return b"".join(byte_list)


# ord good for py2 and py3
_ord = ord if str is bytes else lambda x: x


def _pad_byte(bits):
    """Pad a string of bits with zeros to make its length a multiple of 8."""
    r = len(bits) % 8
    return ((8-r) % 8)*'0' + bits


def get_hash_class(md):
    return getattr(hashes, md.upper(), None)


def get_private_key_from_pem(data):
    return serialization.load_pem_private_key(
        data, None, backend=backends.default_backend())


def get_public_key_from_der(data):
    return serialization.load_der_public_key(
        data, backend=backends.default_backend())


def get_private_key_from_file(path):
    with open(path, 'rb') as f:
        return get_private_key_from_pem(f.read())


def asn1_to_netaddr(octet_string):
    """Translate the ASN1 IP format to netaddr object."""
    if not isinstance(octet_string, rfc5280.univ.OctetString):
        raise TypeError("not an OctetString")

    ip_bytes = octet_string.asOctets()
    if len(ip_bytes) == 4:
        ip_num = struct.unpack(">I", ip_bytes)[0]
        return netaddr.IPAddress(ip_num, 4)
    elif len(ip_bytes) == 16:
        ip_num_front, ip_num_back = struct.unpack(">QQ", ip_bytes)
        ip_num = ip_num_front << 64 | ip_num_back
        return netaddr.IPAddress(ip_num, 6)
    else:
        raise TypeError("ip address is neither v4 nor v6")


def netaddr_to_asn1(ip):
    """Translate the netaddr object to ASN1 IP format."""
    if not isinstance(ip, netaddr.IPAddress):
        raise errors.X509Error("not a real ip address provided")

    return bytes(ip.packed)
