#!/usr/bin/env python

import sys, getopt, select, pybonjour as mdns

# Used to grab the Bonjour name
from SystemConfiguration import SCDynamicStoreCopyLocalHostName


class BonjourRepeater:
	'''
	A class that listens for Bonjour services and repeats them with a new
	service type, at least one additional field in the TXT record, and a
	service name that is modified by adding a prefix.
	'''

	def __init__(self, svctype, rpttype, afields, rfields=[],
			prefix="Repeated", timeout=5, restrict=None):
		'''
		Initialize the class to listen for services of type svctype,
		repeat with a service type rpttype, add TXT record entries in
		the list afields (each with format "key=value"), replace any
		TXT records in the list rfields (each with format "key=value")
		and modify the service name by adding the specified prefix.

		Browse requests will listen for timeout seconds before failing.

		The service will not be repeated if any of the specified TXT
		records in afields already exists. This prevents infinitely
		recursive repeater behavior. The service will also not be
		repeated if restrict is a non-empty string and the target host
		name does not match its contents.
		'''

		# Ensure the prefix is not empty
		if len(prefix) < 1:
			raise ValueError('Prefix must be non-empty.')
		# Ensure at least one new TXT field is specified
		if len(afields) < 1:
			raise ValueError('At least one new TXT field must be specified.')

		# Copy the service and repeat types and the prefix
		self.svctype = svctype
		self.rpttype = rpttype
		self.prefix = prefix

		# Split each new or replaced record field into its own dictionary
		self.afields = dict([[f[0], '='.join(f[1:])]
			for f in [fv.split('=') for fv in afields]])
		try: self.rfields = dict([[f[0], '='.join(f[1:])]
			for f in [fv.split('=') for fv in rfields]])
		except TypeError: self.rfields = {}

		# Copy the timeout value
		self.timeout = timeout

		# A dictionary of repeated Bonjour entries
		self.repeater = {}

		# A buffer to store results from callback processing
		self.cbresult = []

		# This variable controls the browse/repeat thread loop
		self.browse = False

		# Set the restriction string, if desired
		if restrict is not None and len(restrict) > 0: self.restrict = restrict
		else: self.restrict = None


	def register(self, sdRef, flags, err, name, rtype, dom):
		'''
		Invoked after a service registration attempt. Vocalize and note
		the success or failure of the attempt.
		'''

		srvmsg = 'service %s of type %s on domain %s' % (name, rtype, dom)

		if err != mdns.kDNSServiceErr_NoError:
			# Note a failure to register
			print('Failed to register', srvmsg)
			self.cbresult.append(False)
			return

		print('Advertising', srvmsg)
		self.cbresult.append(True)


	def resolver(self, sdRef, flags, ifidx, err, name, tgt, port, txt):
		'''
		Invoked after a service resolution attempt. If successful, the
		target host, port, and TXT record (with added and replaced
		fields) are stored in the result buffer for repetition.
		'''

		# Do nothing if there was a resolution error
		# Resolution attempts will continue
		if err != mdns.kDNSServiceErr_NoError: return

		# Create a TXTRecord type for processing
		txtdict = mdns.TXTRecord.parse(txt)

		# Grab the existing keys
		keys = list(dict(txtdict).keys())

		# Don't continue if the host is restricted and the current
		# target doesn't match the restricted host
		if self.restrict is not None and self.restrict != tgt:
			self.cbresult.append(None)
			return

		# Add new records, failing if a matching record already exists
		for k, v in self.afields.items():
			if k in keys:
				self.cbresult.append(None)
				return
			else: txtdict[k] = v

		# Replace existing records, failing if a matching record doesn't exist
		for k, v in self.rfields.items():
			if k not in keys:
				self.cbresult.append(None)
				return
			else: txtdict[k] = v

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
			print('Stopped repeating', svc)
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
				print('Failed to register service', rptname)
		except mdns.BonjourError: print('Service', svc, 'not repeated')
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
			for v in list(self.repeater.values()): v.close()
			# Reset the repeater dictionary
			self.repeater = {}
			# Close the open browse request
			browseref.close()


def usage (progname):
	print('Usage: %s [-h] <-s type> <-r type> <-f key=value> [-p prefix] [-t timeout] [-F key=value] [-n]' % progname, file=sys.stderr)
	print('  -h: display this message', file=sys.stderr)
	print('  -s type: Bonjour type for which to browse', file=sys.stderr)
	print('  -r type: Bonjour type to use when repeating services', file=sys.stderr)
	print('  -f key=value: add the key=value field to the TXT record', file=sys.stderr)
	print('     Multiple fields may be added with additional -f flags', file=sys.stderr)
	print('  -F key=value: replace the key=value field in the TXT record', file=sys.stderr)
	print('     Multiple fields may be added with additional -F flags', file=sys.stderr)
	print('  -p prefix: string to prepend to service name (default: "Repeated")', file=sys.stderr)
	print('  -t timeout: timeout in seconds for Bonjour requests (default: 5)', file=sys.stderr)
	print('  -n: Repeat all services found on network (default: only repeat local services)', file=sys.stderr)


if __name__ == '__main__':
	# Parse the option list
	optlist, args = getopt.getopt(sys.argv[1:], 's:r:f:F:p:t:hn')

	# Initialize the values for the repeater class
	svcname, rptname, prefix, timeout = [None]*4
	# Initialize lists of fields to be appended or replaced in TXT record
	afields, rfields = [], []
	# By default, only repeat printers shared by the current machine
	noisy = False

	for opt in optlist:
		if opt[0] == '-h':
			usage(sys.argv[0])
			sys.exit(128)
		elif opt[0] == '-s': svcname = opt[1]
		elif opt[0] == '-r': rptname = opt[1]
		elif opt[0] == '-f': afields.append(opt[1])
		elif opt[0] == '-F': rfields.append(opt[1])
		elif opt[0] == '-p': prefix = opt[1]
		elif opt[0] == '-t': timeout = int(opt[1])
		elif opt[0] == '-n': noisy = True

	if svcname is None or rptname is None or len(afields) == 0:
		usage(sys.argv[0])
		sys.exit(128)

	# A dictionary of optional keyword arguments
	kwargs = {}

	if not noisy:
		# Grab the local Bonjour name to restrict repetition
		hostname = SCDynamicStoreCopyLocalHostName(None) + ".local."
		kwargs['restrict'] = hostname

	# Add the desired prefix
	if prefix is not None: kwargs['prefix'] = prefix
	# Set the desired timeout for Bonjour requests
	if timeout is not None: kwargs['timeout'] = timeout

	# Build the desired repeater
	rpt = BonjourRepeater(svcname, rptname, afields, rfields, **kwargs)

	if noisy: print('Starting Bonjour repeater for all network hosts')
	else: print('Starting Bonjour repeater for target host', hostname)

	# Start the listening loop
	try: rpt.repeatloop()
	except KeyboardInterrupt: pass

	print('All repeated Bonjour services removed')
