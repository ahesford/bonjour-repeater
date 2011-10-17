#!/usr/bin/env python

import sys, getopt, select, pybonjour as mdns


class BonjourRepeater:
	'''
	A class that listens for Bonjour services and repeats them with a new
	service type, at least one additional field in the TXT record, and a
	service name that is modified by adding a prefix.
	'''

	def __init__(self, svctype, rpttype, fields, prefix="Repeated", timeout=5):
		'''
		Initialize the class to listen for services of type svctype,
		repeat with a service type rpttype, add TXT record entries in
		the list fields (each with format "key=value"), and modify the
		service name by adding the specified prefix.

		Browse requests will listen for timeout seconds before failing.

		The service will not be repeated if any of the specified TXT
		record fields already exists, or if the service name already
		starts with the prefix. This prevents infinitely recursive
		repeater behavior.
		'''

		# Ensure the prefix is not empty
		if len(prefix) < 1:
			raise ValueError('Prefix must be non-empty.')
		# Ensure at least one new TXT field is specified
		if len(fields) < 1:
			raise ValueError('At least one new TXT field must be specified.')

		# Copy the service and repeat types and the prefix
		self.svctype = svctype
		self.rpttype = rpttype
		self.prefix = prefix

		# Split each new field into its own list where the first item
		# is the key and the second item is the value
		self.fields = [[f[0], '='.join(f[1:])]
				for f in [f.split('=') for f in fields]]

		# Copy the timeout value
		self.timeout = timeout

		# A dictionary of repeated Bonjour entries
		self.repeater = {}

		# A buffer to store results from callback processing
		self.cbresult = []

		# This variable controls the browse/repeat thread loop
		self.browse = False


	def register(self, sdRef, flags, err, name, rtype, dom):
		'''
		Invoked after a service registration attempt. Vocalize and note
		the success or failure of the attempt.
		'''

		srvmsg = 'service %s of type %s on domain %s' % (name, rtype, dom)

		if err != mdns.kDNSServiceErr_NoError:
			# Note a failure to register
			print 'Failed to register', srvmsg
			self.cbresult.append(False)
			return

		print 'Advertising', srvmsg
		self.cbresult.append(True)


	def resolver(self, sdRef, flags, ifidx, err, name, tgt, port, txt):
		'''
		Invoked after a service resolution attempt. If successful, the
		target host, port, and TXT record (with added fields) are
		stored in the result buffer for repetition.
		'''

		# Do nothing if there was a resolution error
		# Resolution attempts will continue
		if err != mdns.kDNSServiceErr_NoError: return

		# Create a TXTRecord type for processing
		txtdict = mdns.TXTRecord.parse(txt)

		# Grab the existing keys
		keys = dict(txtdict).keys()

		# Don't continue if one of the new keys already exists
		for field in self.fields:
			if field[0] in keys:
				self.cbresult.append(None)
				return

		# Add the new keys
		for field in self.fields:
			txtdict[field[0]] = field[1]

		# Store the host, port and TXT record to be repeated
		self.cbresult.append([tgt, port, txtdict])


	def wait(self, sdref):
		'''
		Wait (with timeout) for the provided Bonjour reference to
		complete, then process the result to invoke the provided
		callback.

		After the callback has been called in the call to
		DNSServiceProcessResult, copy and return the result.
		'''

		rec = None
		while not self.cbresult:
			# Wait until the resolution result is ready
			ready = select.select([sdref], [], [], self.timeout)
			if sdref not in ready[0]: break
			# Continue to attempt the query if an error occurred
			mdns.DNSServiceProcessResult(sdref)
		else: rec = self.cbresult.pop()

		return rec


	def browser(self, sdRef, flags, ifidx, err, svc, rtype, dom):
		'''
		Invoked when a new instance of the browsed service is
		identified. Attempt to repeat the service with the new service
		type, modified TXT record and altered service name.
		'''

		# Do nothing if there was a browse error
		if err != mdns.kDNSServiceErr_NoError: return

		# Ignore service names already starting with the prefix
		if svc[:len(self.prefix)] == self.prefix: return

		# Generate a unique key to identify the service to be repeated
		rptkey = ','.join(repr(s) for s in [svc, rtype, dom, ifidx])

		# If the key already exists in the repeater dictionary, then
		# either the identified service has been removed or the service
		# has changed. Either way, stop repeating the old service.
		try:
			# Attempt to deregister the repeated service
			self.repeater[rptkey].close()
			# Attempt to eliminate the service name from the repeat list
			del self.repeater[rptkey]
			print 'Stopped repeating', svc
		except KeyError: pass

		# Nothing to do if the service is noted as removed
		if not (flags & mdns.kDNSServiceFlagsAdd): return

		# Add the prefix (and a space) to the existing service name
		rptname = self.prefix + ' ' + svc

		# Attempt to resolve the advertised service on the interface
		resref = mdns.DNSServiceResolve(0, ifidx, svc, rtype, dom, self.resolver)

		try:
			# Wait for the resolution to finish and return the record data
			rec = self.wait(resref)

			# If the resolution attempt yielded no useful result,
			# throw an exception to skip advertisement and ensure
			# the lookup is closed
			if rec is None: raise mdns.BonjourError(mdns.kDNSServiceErr_Unknown)

			# Register the new service on the same interface
			regref = mdns.DNSServiceRegister(0, ifidx,
					rptname, self.rpttype, dom,
					rec[0], rec[1], rec[2], self.register)

			try:
				# Copy the finished registration if successful
				if self.wait(regref): self.repeater[rptkey] = regref
				else: raise mdns.BonjourError(mdns.kDNSServiceErr_Unknown)
			except mdns.BonjourError:
				# Only close the reference in the event of a failure
				regref.close()
				print 'Failed to register service', rptname
		except mdns.BonjourError: print 'Service', svc, 'not repeated'
		finally: resref.close()

	def repeatloop(self):
		'''
		A loop that listens for the desired Bonjour service types and
		repeats all it finds. The loop will continue indefinitely so it
		should be invoked in a separate thread if additional action is
		required. In this case, just set self.browse to False to
		terminate the listening.

		When the loop is terminated, close the browse request.

		Listening is done for timeout seconds so that the loop can be
		terminated if desired. After termination, all repeated services
		are removed.
		'''

		# Attempt a browse of the service type
		browseref = mdns.DNSServiceBrowse(
				regtype = self.svctype, callBack = self.browser)

		self.browse = True

		try:
			while self.browse:
				ready = select.select([browseref], [], [], self.timeout)
				if browseref in ready[0]:
					mdns.DNSServiceProcessResult(browseref)
		finally:
			# Attempt to close all open repeater references
			for v in self.repeater.values(): v.close()
			# Reset the repeater dictionary
			self.repeater = {}
			# Close the open browse request
			browseref.close()


def usage (progname):
	print >> sys.stderr, 'Usage: %s [-h] <-s type> <-r type> <-f key=value> [-p prefix] [-t timeout]' % progname
	print >> sys.stderr, '\t-h: display this message'
	print >> sys.stderr, '\t-s type: Bonjour type for which to browse'
	print >> sys.stderr, '\t-r type: Bonjour type to use when repeating services'
	print >> sys.stderr, '\t-f key=value: add the key=value field to the TXT record'
	print >> sys.stderr, '\t   Multiple fields may be added with additional -f flags'
	print >> sys.stderr, '\t-p prefix: string to prepend to service name (default: Repeated)'
	print >> sys.stderr, '\t-t timeout: timeout in seconds for Bonjour requests (default: 5)'


if __name__ == '__main__':
	# Parse the option list
	optlist, args = getopt.getopt(sys.argv[1:], 's:r:f:p:t:h')

	# Initialize the values for the repeater class
	svcname, rptname, prefix, timeout = [None]*4
	fields = []

	for opt in optlist:
		if opt[0] == '-h':
			usage(sys.argv[0])
			sys.exit(128)
		elif opt[0] == '-s':
			svcname = opt[1]
		elif opt[0] == '-r':
			rptname = opt[1]
		elif opt[0] == '-f':
			fields.append(opt[1])
		elif opt[0] == '-p':
			prefix = opt[1]
		elif opt[0] == '-t':
			timeout = int(opt[1])

	if svcname is None or rptname is None or len(fields) == 0:
		usage(sys.argv[0])
		sys.exit(128)

	# A dictionary of optional keyword arguments
	optionals = {}
	if prefix is not None: optionals['prefix'] = prefix
	if timeout is not None: optionals['timeout'] = timeout

	# Build the desired repeater
	rpt = BonjourRepeater(svcname, rptname, fields, **optionals)

	print 'Starting Bonjour repeater'

	# Start the listening loop
	try: rpt.repeatloop()
	except KeyboardInterrupt: pass

	print 'All repeated Bonjour services removed'
