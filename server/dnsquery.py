from __future__ import print_function

import logging
import logging.config
import dbpool
import dns.resolver

logging.config.fileConfig('logging.config')
logger = logging.getLogger('dnsquery')


class Record:

	def __init__(self, id, domain_id, name, type, content, ttl, priority, change_date, disabled, order_name, auth):

		self.id = id
		self.domain_id = domain_id
		self.name = name
		self.type = type
		self.content = content
		self.ttl = ttl
		self.priority = priority
		self.change_date = change_date
		self.disabled = disabled
		self.order_name = order_name
		self.auth = auth

	def serialize(self):
		return {'id': self.id, 'domain_id': self.domain_id, 'name': self.name, 'type': self.type,
				'content': self.content, 'ttl': self.ttl, 'priority': self.priority, 'change_date': self.change_date,
				'disabled': self.disabled, 'order_name': self.order_name, 'auth': self.auth}


class DNSQuery:

	# DNS Record Types

	Q_TYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 35: 'NAPTR'}

	# Response code

	NO_ERROR = 0
	FORMAT_ERROR = 1
	SERVER_FAILURE = 2
	NAME_ERROR = 3
	NOT_IMPLEMENTED = 4
	REFUSED = 5
	YXDOMAIN = 6
	YX_RR_SET = 7
	NX_RR_SET = 8
	NOT_AUTH = 9
	NOT_ZONE = 10

	def __init__(self, thread_id, buf):

		data = bytearray(buf)
		if logger.level == logging.DEBUG:
			output = self.format_packet(data)
			logger.debug('\nDNS Query:\n' + output)

		first_byte = data.pop(0)
		second_byte = data.pop(0)

		self.tid = first_byte << 8 | second_byte

		first_byte = data.pop(0)
		second_byte = data.pop(0)
		flags_and_code = first_byte << 8 | second_byte

		self.qr = flags_and_code >> 15 & 1
		self.opcode = flags_and_code >> 11 & 15

		# flags
		# qr - query/response
		# aa - Authoriative Answer
		# tc - Truncation
		# rd - Recursion Desired
		# ra - Recursion Available

		self.aa = flags_and_code >> 10 & 1
		self.tc = flags_and_code >> 9 & 1
		self.rd = flags_and_code >> 8 & 1
		self.ra = flags_and_code >> 7 & 1
		self.zero = flags_and_code >> 4 & 7
		self.rcode = DNSQuery.NO_ERROR

		first_byte = data.pop(0)
		second_byte = data.pop(0)
		self.qdcount = first_byte << 8 | second_byte
		first_byte = data.pop(0)
		second_byte = data.pop(0)
		self.ancount = first_byte << 8 | second_byte
		first_byte = data.pop(0)
		second_byte = data.pop(0)
		self.nscount = first_byte << 8 | second_byte
		first_byte = data.pop(0)
		second_byte = data.pop(0)
		self.arcount = first_byte << 8 | second_byte

		label = data.pop(0)
		self.qname = []

		while int(label) != 0:
			self.qname.append(label)
			for index in range(int(label)):
				label = data.pop(0)
				self.qname.append(label)
			label = data.pop(0)
		self.qname.append(label)

		qname_copy = list(self.qname)
		self.domain = label_to_domain(qname_copy)
		first_byte = data.pop(0)
		second_byte = data.pop(0)
		self.qtype = first_byte << 8 | second_byte
		self.type = DNSQuery.Q_TYPES[self.qtype]

		first_byte = data.pop(0)
		second_byte = data.pop(0)
		self.qclass = first_byte << 8 | second_byte

		if logger.level == logging.DEBUG:
			logger.debug('\n Thread ID = %d \n domain = %s \n qtype = %d \n type = %s \n qclass = %02x \n tid = %02x \n '
						 'qr = %02x \n opcode = %02x \n aa = %02x \n tc = %02x \n rd = %02x \n zero = %02x \n '
						 'rcode = %02x \n qtype = %02x \n qclass = %02x \n qdcount = %02x \n ancount = %02x \n '
						 'nscount = %02x \n arcount = %02x', thread_id, self.domain, self.qtype, self.type, self.qclass, self.tid, self.qr,
						 self.opcode, self.aa, self.tc, self.rd, self.zero, self.rcode, self.qtype, self.qclass,
						 self.qdcount, self.ancount, self.nscount, self.arcount)



	def format_packet(self,data):

		cursor = 0
		output = ''
		while cursor < len(data):
			output += '{0:0{1}x}'.format(cursor, 4) + '  '
			for index in range(16):
				if cursor >= len(data):
					break
				else:
					output += '{0:0{1}x}'.format(data[cursor], 2) + ' '
					cursor += 1
			output += '\n'
		return output

	def serialize_header(self):
		pass


def label_to_domain(labels):

	if logger.level == logging.DEBUG:
		logger.debug('\n labels: %s', labels)
	label = labels.pop(0)
	domain = ''

	while int(label) != 0:
		for index in range(int(label)):
			label = labels.pop(0)
			domain += chr(label)
		label = labels.pop(0)
		domain += '.'
	return domain


def get_records(domain, type):

	if logger.level == logging.INFO:
		output = "\nQuery Name: " + domain + " Type: " + type
		logger.info(output)
	cursor = None
	conn = None
	records = []
	try:
		db = dbpool.get_database()
		conn = db.get_connection()
		cursor = conn.cursor()
		query = 'SELECT id, domain_id, name, type, content, ttl, priority, change_date, disabled, order_name, auth' \
					' FROM records WHERE name = %s and type = %s'
		cursor.execute(query, (domain, type))
		rs = cursor.fetchall()

		for row in rs:
			if row[8] == 1:
				continue
			id = row[0]
			domain_id = row[1]
			name = row[2]
			type = row[3]
			content = row[4]
			ttl = row[5]
			priority = row[6]
			change_date = row[7]
			disabled = row[8]
			order_name = row[9]
			auth = row[10]

			record = Record(id, domain_id, name, type, content, ttl, priority, change_date, disabled, order_name,
								auth)
			records.append(record)

			if logger.level == logging.DEBUG:
				for record in records:
					logger.debug(record.serialize())
	finally:
		if cursor is not None:
			cursor.close()
		if conn is not None:
			conn.close()
		return records


def get_records_by_domain_id(domain_id, type):

		cursor = None
		conn = None
		records = []
		try:
			db = dbpool.get_database()
			conn = db.get_connection()
			cursor = conn.cursor()
			query = 'SELECT id, domain_id, name, type, content, ttl, priority, change_date, disabled, order_name, auth' \
					' FROM records WHERE domain_id= %s and type = %s'
			cursor.execute(query, (domain_id, type))
			rs = cursor.fetchall()

			for row in rs:
				id = row[0]
				domain_id = row[1]
				name = row[2]
				type = row[3]
				content = row[4]
				ttl = row[5]
				priority = row[6]
				change_date = row[7]
				disabled = row[8]
				order_name = row[9]
				auth = row[10]

				record = Record(id, domain_id, name, type, content, ttl, priority, change_date, disabled, order_name,
								auth)
				records.append(record)

			if logger.level == logging.DEBUG:
				for record in records:
					logger.debug(record.serialize())
		finally:
			if cursor is not None:
				cursor.close()
			if conn is not None:
				conn.close()
			return records

def do_external_query(domain, qtype, dns1, dns2):
	answers = dns.resolver.query(domain, 'A')
	records = []
	for rdata in answers:
		record = Record(None, None, domain, 'A', rdata.to_text(), 69, None, None, None, None, None)
		records.append(record)
	return records


