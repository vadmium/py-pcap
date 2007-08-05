#! /usr/bin/env python

import pcap
import sys

for fn in sys.argv[1:]:
    p = pcap.open(file(fn))
    o = pcap.open(file(fn + '.new', 'w'))

    print "===================", fn
    print "  Version ", p.version
    print "  thiszone", p.thiszone
    print "  sigfigs ", p.sigfigs
    print "  snaplen ", p.snaplen
    print "  linktype", p.linktype

    for pkt in p:
        print pkt
        o.write(pkt)




