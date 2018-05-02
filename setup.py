#!/usr/bin/env python
'''
bonjour-repeater.py: Rebroadcast Bonjour services with additional records

bonjour-repeater.py listens for local Bonjour services of a specific type and
rebroadcasts them with a prefix added to the service name, adding or replacing
fields in the record and optionally changing the service type.
'''

# Copyright (c) 2015--2018 Andrew J. Hesford. All rights reserved.
# Restrictions are listed in the LICENSE file distributed with this package.

DOCLINES = __doc__.split('\n')
VERSION = '1.0'

if __name__ == '__main__':
	from setuptools import setup

	setup(name='bonjour-repeater',
			version=VERSION,
			description=DOCLINES[0],
			long_description='\n'.join(DOCLINES[2:]),
			author='Andrew J. Hesford',
			author_email='ajh@sideband.org',
			platforms=['any'], license='BSD',
			scripts=['bonjour-repeater.py',],
			install_requires=[
				'pyobjc-framework-SystemConfiguration',
				'pybonjour',
			],
		)
