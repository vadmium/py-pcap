#! /usr/bin/python

import struct

try:  # Python 3
    import builtins
except ImportError:  # Python < 3
    import __builtin__ as builtins

# http://www.tcpdump.org/linktypes.html
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_AX25 = 3
LINKTYPE_IEEE802_5 = 6
LINKTYPE_ARCNET_BSD = 7
LINKTYPE_SLIP = 8
LINKTYPE_PPP = 9
LINKTYPE_FDDI = 10
LINKTYPE_PPP_HDLC = 50
LINKTYPE_PPP_ETHER = 51
LINKTYPE_ATM_RFC1483 = 100
LINKTYPE_RAW = 101
LINKTYPE_C_HDLC = 104
LINKTYPE_IEEE802_11 = 105
LINKTYPE_FRELAY = 107
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LTALK = 114
LINKTYPE_PFLOG = 117
LINKTYPE_IEEE802_11_PRISM = 119
LINKTYPE_IP_OVER_FC = 122
LINKTYPE_SUNATM = 123
LINKTYPE_IEEE802_11_RADIOTAP = 127
LINKTYPE_ARCNET_LINUX = 129
LINKTYPE_APPLE_IP_OVER_IEEE1394 = 138
LINKTYPE_MTP2_WITH_PHDR = 139
LINKTYPE_MTP2 = 140
LINKTYPE_MTP3 = 141
LINKTYPE_SCCP = 142
LINKTYPE_DOCSIS = 143
LINKTYPE_LINUX_IRDA = 144
LINKTYPE_USER = 147  # _USER0-_USER15 = 147-162
LINKTYPE_IEEE802_11_AVS = 163
LINKTYPE_BACNET_MS_TP = 165
LINKTYPE_PPP_PPPD = 166
LINKTYPE_GPRS_LLC = 169
LINKTYPE_LINUX_LAPD = 177
LINKTYPE_BLUETOOTH_HCI_H4 = 187
LINKTYPE_USB_LINUX = 189
LINKTYPE_PPI = 192
LINKTYPE_IEEE802_15_4 = 195
LINKTYPE_SITA = 196
LINKTYPE_ERF = 197
LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201
LINKTYPE_AX25_KISS = 202
LINKTYPE_LAPD = 203
LINKTYPE_PPP_WITH_DIR = 204
LINKTYPE_C_HDLC_WITH_DIR = 205
LINKTYPE_FRELAY_WITH_DIR = 206
LINKTYPE_IPMB_LINUX = 209
LINKTYPE_IEEE802_15_4_NONASK_PHY = 215
LINKTYPE_USB_LINUX_MMAPPED = 220
LINKTYPE_FC_2 = 224
LINKTYPE_FC_2_WITH_FRAME_DELIMS = 225
LINKTYPE_IPNET = 226
LINKTYPE_CAN_SOCKETCAN = 227
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_IEEE802_15_4_NOFCS = 230
LINKTYPE_DBUS = 231
LINKTYPE_DVB_CI = 235
LINKTYPE_MUX27010 = 236
LINKTYPE_STANAG_5066_D_PDU = 237
LINKTYPE_NFLOG = 239
LINKTYPE_NETANALYZER = 240
LINKTYPE_NETANALYZER_TRANSPARENT = 241
LINKTYPE_IPOIB = 242
LINKTYPE_MPEG_2_TS = 243
LINKTYPE_NG40 = 244
LINKTYPE_NFC_LLCP = 245
LINKTYPE_INFINIBAND = 247
LINKTYPE_SCTP = 248
LINKTYPE_USBPCAP = 249
LINKTYPE_RTAC_SERIAL = 250
LINKTYPE_BLUETOOTH_LE_LL = 251
LINKTYPE_NETLINK = 253
LINKTYPE_BLUETOOTH_LINUX_MONITOR = 254
LINKTYPE_BLUETOOTH_BREDR_BB = 255
LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256
LINKTYPE_PROFIBUS_DL = 257
LINKTYPE_PKTAP = 258
LINKTYPE_EPON = 259
LINKTYPE_IPMI_HPM_2 = 260

_MAGIC = 0xA1B2C3D4

class pcap:
    def __init__(self, stream, mode='rb', snaplen=65535,
    linktype=LINKTYPE_ETHERNET):
        try:
            self.stream = builtins.open(stream, mode)
        except TypeError:
            self.stream = stream
        try:
            # Try reading
            hdr = self.stream.read(24)
        except IOError:
            hdr = None

        if hdr:
            # We're in read mode
            self._endian = None
            for endian in '<>':
                (self.magic,) = struct.unpack(endian + 'I', hdr[:4])
                if self.magic == _MAGIC:
                    self._endian = endian
                    break
            if not self._endian:
                raise IOError('Not a pcap file')
            (self.magic, version_major, version_minor,
             self.thiszone, self.sigfigs,
             self.snaplen, self.linktype) = struct.unpack(self._endian + 'IHHIIII', hdr)
            if (version_major, version_minor) != (2, 4):
                raise IOError('Cannot handle file version %d.%d' % (version_major,
                                                                    version_minor))
        else:
            # We're in write mode
            self._endian = '='
            self.magic = _MAGIC
            version_major = 2
            version_minor = 4
            self.thiszone = 0
            self.sigfigs = 0
            self.snaplen = snaplen
            self.linktype = linktype
            hdr = struct.pack(self._endian + 'IHHIIII',
                              self.magic, version_major, version_minor,
                              self.thiszone, self.sigfigs,
                              self.snaplen, self.linktype)
            self.stream.write(hdr)
        self.version = (version_major, version_minor)

    def read(self):
        hdr = self.stream.read(16)
        if not hdr:
            return
        (tv_sec, tv_usec, caplen, length) = struct.unpack(self._endian + 'IIII', hdr)
        datum = self.stream.read(caplen)
        return ((tv_sec, tv_usec, length), datum)

    def write(self, packet):
        (header, datum) = packet
        (tv_sec, tv_usec, length) = header
        hdr = struct.pack(self._endian + 'IIII', tv_sec, tv_usec, length, len(datum))
        self.stream.write(hdr)
        self.stream.write(datum)

    def __iter__(self):
        while True:
            r = self.read()
            if not r:
                break
            yield r


open = pcap
open_offline = pcap


if __name__ == '__main__':
    p = open('test.pcap', 'wb')  # Create a new file
    p.write(((0, 0, 3), b'foo')) # Add a packet
    p.write(((0, 0, 3), b'bar'))
    del p
    p = open(builtins.open('test.pcap', 'rb')) # Also takes file objects
    assert ((p.version, p.thiszone, p.sigfigs, p.snaplen, p.linktype) ==
            ((2, 4), 0, 0, 65535, 1))
    assert ([i for i in p] == [((0, 0, 3), b'foo'), ((0, 0, 3), b'bar')])
