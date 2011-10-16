#!/usr/bin/env python

import select
import sys
import pybonjour as mdns


# The DNS type for browsing
browsetype = "_ipp._tcp"
# Add a _universal subtype when repeating the record
rpttype = browsetype + ",_universal"

# A prefix to add to repeated service names
prefix = "AirPrint"

# The Unirast key-value pair as a TXT record field
urf = ('URF', 'W8,CP1,RS600-600')

# Timeout when attempting to resolve browsed records
timeout  = 5

# A dictionary of repeated mDNS entries
repeater = {}

# This is used to store results from callback functions
cbresult = []


def register(sdRef, flags, errorCode, name, regtype, domain):
	'''
	This function is invoked after a service registration. It does nothing
	but announce the registration for logging.
	'''

	srvmsg = 'service %s of type %s on domain %s' % (name, regtype, domain)

	if errorCode != mdns.kDNSServiceErr_NoError: 
		# Note a failure to register and remove the 
		print 'Failed to register', srvmsg
		cbresult.append(False)
		return 

	print 'Advertising', srvmsg
	cbresult.append(True)


def resolver(sdRef, flags, interfaceIndex,
		errorCode, fullname, hosttarget, port, txtRecord):
	'''
	This function is invoked after a successful service resolution, or when
	the resolution fails. If resolution was successful, the target host,
	port, and TXT record (with an URF field added, if necessary) are stored
	in the resolved list to be processed by the repeater.
	'''
	# Do nothing if there was a resolution error
	if errorCode != mdns.kDNSServiceErr_NoError: return
	
	# Create a TXTRecord type for processing
	txtdict = mdns.TXTRecord.parse(txtRecord)

	# Ignore entries that already have a Unirast field
	if urf[0] in dict(txtdict).keys():
		cbresult.append(None)
		return

	# Add a Unirast field if there is none
	txtdict[urf[0]] = urf[1]

	# Store the host, port and TXT record to be repeated
	cbresult.append([hosttarget, port, txtdict])


def waitmdnscb(sdref):
	'''
	Give the server a chance to respond or timeout, and grab the result.
	'''

	rec = None
	while not cbresult:
		# Wait until the resolution result is ready
		ready = select.select([sdref], [], [], timeout)
		if sdref not in ready[0]: break
		# Continue to attempt the query if an error occurred
		mdns.DNSServiceProcessResult(sdref)
	else: rec = cbresult.pop()

	return rec


def browser(sdRef, flags, interfaceIndex,
		errorCode, serviceName, regtype, replyDomain):
	'''
	This function is invoked when an instance of the browsed service is
	identified, or when the browse attempt fails. If the instance can be
	successfully resolved, a new service is created and advertised by
	prepending a prefix to the service name, modifying the service type,
	and copying the target host, port and modified TXT record of the
	original service.
	'''
	# Do nothing if there was a browse error
	if errorCode != mdns.kDNSServiceErr_NoError: return

	# Generate a unique key to identify the service to be repeated
	rptkey = ','.join(repr(s)
			for s in [serviceName, regtype, replyDomain, interfaceIndex])

	try:
		# Attempt to deregister the repeated service
		repeater[rptkey].close()
		# Attempt to eliminate the serviceName from the repeat list
		del repeater[rptkey]
		print 'Stopped repeating', serviceName
	except KeyError: pass

	# The service has been flagged as removed, nothing left to do
	if not (flags & mdns.kDNSServiceFlagsAdd): return
	# Don't repeat services whose names start with the prefix
	if serviceName[:len(prefix)] == prefix: return

	# Create a new service name by prepending a prefix to the old one
	rptname = prefix + ' ' + serviceName

	# The service has been added, attempt to resolve the details
	resref = mdns.DNSServiceResolve(0, interfaceIndex,
			serviceName, regtype, replyDomain, resolver)

	try:
		# Wait for the resolution to finish and return the record data
		rec = waitmdnscb(resref)
		if rec is None: raise mdns.BonjourError(mdns.kDNSServiceErr_Unknown)

		# Register the new service
		regref = mdns.DNSServiceRegister(0, interfaceIndex, rptname,
				rpttype, replyDomain, rec[0], rec[1], rec[2], register)
		
		try:
			# Copy the finished registration if successful
			if waitmdnscb(regref): repeater[rptkey] = regref
			else: raise mdns.BonjourError(mdns.kDNSServiceErr_Unknown)
		except mdns.BonjourError:
			# Only close the reference in the event of a failure
			regref.close()
			print 'Failed to register service', rptname
	except mdns.BonjourError: print 'Service', serviceName, 'not repeated'
	finally: resref.close()


# Attempt a browse of all IPP printers in the default domain
brwref = mdns.DNSServiceBrowse(regtype = browsetype, callBack = browser)

try:
	# Continue listening indefinitely
	# Invoke the resolver whenever a instance is found
	while True:
		ready = select.select([brwref], [], [])
		if brwref in ready[0]: mdns.DNSServiceProcessResult(brwref)
except KeyboardInterrupt: pass
finally: brwref.close()
