#! /usr/bin/env python

from distutils.core import setup, Extension

module = Extension('pcap',
                   sources = ['pcap.c'])
setup(name = 'pcap',
      version = '1.0',
      description = 'Less-sucky pcap interface',
      author = 'Neale Pickett',
      author_email = 'neale@woozle.org',
      url = 'http://woozle.org/~neale/repos/',
      ext_modules = [module])
