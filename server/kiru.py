from __future__ import print_function

import logging
import logging.config
import os
import socket
import sys
from Queue import Queue
from threading import Thread

import mysql.connector

import dnsquery
from dnsquery import DNSQuery


def tcp_connector(host, port):

	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.bind((host, port))
		sock.listen(5)
		flag = TCP_FLAG

		logger.info("Starting TCP connector on port " + str(port) + "...")

		while True:
			conn, address = sock.accept()
			buf = conn.recv(TCP_BUFFER)
			sock_pair = [conn, address, buf, flag]
			queue.put(sock_pair)

	except socket.error as msg:
		logger.error("Bind failed.  \nError code: " + str(msg[0]) + ' Message ' + msg[1])
		sys.exit()


def udp_connector(host, port):

	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.bind((host, port))
		flag = UDP_FLAG
		logger.info("Starting UDP connector on port " + str(port) + "...")

		while True:
			buf, address = sock.recvfrom(UDP_BUFFER)
			sock_pair = [sock, address, buf, flag]
			queue.put(sock_pair)

	except socket.error as msg:
		logger.error("Bind failed.  \nError code: " + str(msg[0]) + ' Message ' + msg[1])
		sys.exit()


def handle_request(thread_id, q, server_config):

	while True:

		sock_pair = q.get()
		sock, address, buf, flag = sock_pair
		proxy_mode = server_config.get('proxy')
		query = DNSQuery(thread_id, buf)
		try:
			ans_records = dnsquery.get_records(query.domain, query.type)
		except mysql.connector.Error as e:
			logger.error(e)
			query.rcode = DNSQuery.SERVER_FAILURE

		# query external dns if record not in db and proxy mode is True and A lookup
		if not ans_records and proxy_mode and query.qtype == 1:

			dns1 = server_config.get('dns1')
			dns2 = server_config.get('dns2')
			if logger.level == logging.DEBUG:
				logger.debug("kiru.py: dnsquery.do_external_query")
			ans_records = dnsquery.do_external_query(query.domain, query.qtype, dns1, dns2)


		ns_records = []
		additional_records = []

		# check if authoritative or not

		for record in ans_records:
			if record.auth == 1:
				query.aa = 1
				domain_id = record.domain_id

		if query.aa == 1 and query.type != 'SOA':
			ns_records = dnsquery.get_records_by_domain_id(domain_id, 'NS')
			for record in ns_records:
				a_records = dnsquery.get_records(record.content, 'A')
				aaaa_records = dnsquery.get_records(record.content, 'AAAA')
				additional_records.extend(a_records)
				additional_records.extend(aaaa_records)

		if logger.level == logging.INFO:
			output = "\nQuery name: " + record.name + " Response: " + record.content
			logger.info(output)
		if logger.level == logging.DEBUG:
			output = "\nans_records\n"
			for record in ans_records:
				output += record.name + " " + record.content + "\n"
			output += "\nns_records\n"
			for record in ns_records:
				output += record.name + " " + record.content + "\n"
			output += "\nadditional_records\n"
			for record in additional_records:
				output += record.name + " " + record.content + "\n"
			logger.debug(output)

		answers = bytearray()

		for record in ans_records:
			answers = encode_record(answers, record, None)

		authority = bytearray()

		for record in ns_records:
			authority = encode_record(authority, record, None)

		additional = bytearray()

		for record in additional_records:
			additional = encode_record(additional, record, record.name)

		query.ancount = len(ans_records)
		query.nscount = len(ns_records)
		query.arcount = len(additional_records)

		# Prepare response

		header = bytearray()
		query.qr = 1
		header.append(query.tid >> 8)
		header.append(query.tid & 255)

		first_byte = query.qr << 7 | (query.opcode << 6 & 120) | (query.aa << 2 & 4) | (query.tc << 1 & 2) \
					 | (query.rd & 1)
		second_byte = query.ra << 7 | query.zero << 6 | query.rcode

		header.append(first_byte)
		header.append(second_byte)

		header.append(query.qdcount >> 8)
		header.append(query.qdcount & 255)

		header.append(query.ancount >> 8)
		header.append(query.ancount & 255)

		header.append(query.nscount >> 8)
		header.append(query.nscount & 255)

		header.append(query.arcount >> 8)
		header.append(query.arcount & 255)

		queries = bytearray()

		for element in query.qname:
			queries.append(element)

		queries.append(query.qtype >> 8)
		queries.append(query.qtype & 255)

		queries.append(query.qclass >> 8)
		queries.append(query.qclass & 255)

		response = bytearray()

		# package response

		response.extend(header)
		response.extend(queries)
		response.extend(answers)
		response.extend(authority)
		response.extend(additional)

		if logger.level == logging.DEBUG:
			output = query.format_packet(response)
			logger.debug("\nDNS Response:\n" + output)

		if flag == TCP_FLAG:
			sock.send(query.tid)

		else:
			sock.sendto(response, address)
		q.task_done()


def encode_record(byte_array, record, name):

	for key, value in DNSQuery.Q_TYPES.iteritems():
		if value == record.type.upper():
			type = key

	if name is None:

		# Add C0 0C for message compression

		byte_array.append(192)
		byte_array.append(12)
	else:
		label_list = name.split('.')
		if label_list[len(label_list) - 1] == '':
			label_list.pop()

		for label in label_list:
			byte_array.append(len(label))
			byte_array.extend(label.encode('ascii'))

		byte_array.append(0)

	byte_array.append(type >> 8)
	byte_array.append(type & 255)

	# hardcoding record class to Internet.  No support for Chaos, Hesiod or other unknown class types

	byte_array.append(0)
	byte_array.append(1)

	byte_array.append(record.ttl >> 24)
	byte_array.append(record.ttl >> 16 & 255)
	byte_array.append(record.ttl >> 8 & 255)
	byte_array.append(record.ttl & 255)

	# Encoding for A Record

	if str(record.type).upper() == 'A':
		length = 4
		byte_array.append(length >> 8)
		byte_array.append(length & 255)
		ip_list = record.content.split('.')
		for number in ip_list:
			byte_array.append(int(number))

	# Encoding for TXT record

	if str(record.type).upper() == 'TXT':
		length = len(record.content)
		data_length = length + 1
		byte_array.append(data_length >> 8)
		byte_array.append(data_length & 255)
		byte_array.append(length & 255)
		byte_array.extend(record.content.encode('ascii'))

	# Encoding for CNAME, NS and PTR records

	if str(record.type).upper() == 'CNAME' or str(record.type).upper() == 'NS' or str(record.type).upper() == 'PTR':
		label_list = record.content.split('.')
		if label_list[len(label_list) - 1] == '':
			label_list.pop()

		length = 0
		for label in label_list:
			length += len(label) + 1
		length += 1
		byte_array.append(length >> 8)
		byte_array.append(length & 255)
		for label in label_list:
			byte_array.append(len(label))
			byte_array.extend(label.encode('ascii'))


		byte_array.append(0)

	# Encoding for MX record

	if str(record.type).upper() == 'MX':
		label_list = record.content.split('.')
		if label_list[len(label_list) - 1] == '':
			label_list.pop()

		length = 2  # start with 2 bytes for preference
		for label in label_list:
			length += len(label) + 1
		length += 1
		byte_array.append(length >> 8)
		byte_array.append(length & 255)
		byte_array.append(record.priority >> 8)
		byte_array.append(record.priority & 255)
		for label in label_list:
			byte_array.append(len(label))
			byte_array.extend(label.encode('ascii'))

		byte_array.append(0)

	# Encoding for AAAA record

	if str(record.type).upper() == 'AAAA':
		ip_list = record.content.split(':')
		length = 16
		byte_array.append(length >> 8)
		byte_array.append(length & 255)
		for ip in ip_list:
			byte_array.append(int(ip[:2], 16))
			byte_array.append(int(ip[2:], 16))

	# Encoding for SRV record

	if str(record.type).upper() == 'SRV':
		content_list = record.content.split(' ')
		priority = int(content_list[0])
		weight = int(content_list[1])
		port = int(content_list[2])
		target = content_list[3]

		target_list = target.split('.')
		if target_list[len(target_list) - 1] == '':
			target_list.pop()
		length = 6  # start at 6 bytes
		for label in target_list:
			length += len(label) + 1
		length += 1

		byte_array.append(length >> 8)
		byte_array.append(length & 255)
		byte_array.append(priority >> 8)
		byte_array.append(priority & 255)
		byte_array.append(weight >> 8)
		byte_array.append(weight & 255)
		byte_array.append(port >> 8)
		byte_array.append(port & 255)
		for label in target_list:
			byte_array.append(len(label))
			byte_array.extend(label.encode('ascii'))
		byte_array.append(0)

	# Encoding for NAPTR record

	if str(record.type).upper() == 'NAPTR':
		content_list = record.content.split(' ')
		order = int(content_list[0])
		preference = int(content_list[1])
		temp = str(content_list[2]).split('\"')
		if len(temp) > 2:
			flags = temp[1]
		else:
			flags = ''
		temp = str(content_list[3]).split('\"')
		if len(temp) > 2:
			services = temp[1]
		else:
			services = ''
		temp = str(content_list[4]).split('\"')
		if len(temp) > 2:
			regexp = temp[1]
		else:
			regexp = ''
		replace = str(content_list[5])
		replace_list = replace.split('.')
		if replace_list[len(replace_list) - 1] == '':
			replace_list.pop()

		length = 7 + len(services) + len(flags) + len(regexp)
		for label in replace_list:
			length += len(label) + 1
		length += 1
		byte_array.append(length >> 8)
		byte_array.append(length & 255)
		byte_array.append(order >> 8)
		byte_array.append(order & 255)
		byte_array.append(preference >> 8)
		byte_array.append(preference & 255)
		byte_array.append(len(flags))
		byte_array.extend(flags.encode('ascii'))
		byte_array.append(len(services))
		byte_array.extend(services.encode('ascii'))
		byte_array.append(len(regexp))
		byte_array.extend(regexp.encode('ascii'))
		for label in replace_list:
			byte_array.append(len(label))
			byte_array.extend(label.encode('ascii'))
		byte_array.append(0)

	# Encoding for SOA record

	if str(record.type).upper() == 'SOA':
		content_list = record.content.split(' ')
		m_name = content_list[0]
		r_name = content_list[1]
		serial = int(content_list[2])
		refresh = int(content_list[3])
		retry = int(content_list[4])
		expire = int(content_list[5])
		ttl = int(content_list[6])

		length = 20 #length of fixed byte fields

		label_list = m_name.split('.')
		if label_list[len(label_list) - 1] == '':
			label_list.pop()
		for label in label_list:
			length += len(label) + 1
		length += 1
		label_list = r_name.split('.')
		if label_list[len(label_list) - 1] == '':
			label_list.pop()
		for label in label_list:
			length += len(label) + 1
		length += 1
		byte_array.append(length >> 8)
		byte_array.append(length & 255)

		label_list = m_name.split('.')
		for label in label_list:
			byte_array.append(len(label))
			byte_array.extend(label.encode('ascii'))
		#byte_array.append(0)

		label_list = r_name.split('.')
		for label in label_list:
			byte_array.append(len(label))
			byte_array.extend(label.encode('ascii'))
		#byte_array.append(0)

		byte_array.append(serial >> 24)
		byte_array.append(serial >> 16 & 255)
		byte_array.append(serial >> 8 & 255)
		byte_array.append(serial & 255)

		byte_array.append(refresh >> 24)
		byte_array.append(refresh >> 16 & 255)
		byte_array.append(refresh >> 8 & 255)
		byte_array.append(refresh & 255)

		byte_array.append(retry >> 24)
		byte_array.append(retry >> 16 & 255)
		byte_array.append(retry >> 8 & 255)
		byte_array.append(retry & 255)

		byte_array.append(expire >> 24)
		byte_array.append(expire >> 16 & 255)
		byte_array.append(expire >> 8 & 255)
		byte_array.append(expire & 255)

		byte_array.append(ttl >> 24)
		byte_array.append(ttl >> 16 & 255)
		byte_array.append(ttl >> 8 & 255)
		byte_array.append(ttl & 255)

	return byte_array



def main():

	with open(os.path.join(os.path.dirname(__file__), "config.properties"), 'r') as config:
		server_config = {}
		for line in config:
			temp = line.split('=')
			if temp[0] == 'threads':
				threads = int(temp[1])
			if temp[0] == 'host':
				server_config['host'] = temp[1].rstrip('\n')
			if temp[0] == 'port':
				server_config['port'] = int(temp[1].rstrip('\n'))
			if temp[0] == 'proxy':
				if temp[1].rstrip('\n') == 'yes':
					server_config['proxy'] = True
				else:
					server_config['proxy'] = False
			if temp[0] == 'dns1':
				server_config['dns1'] = temp[1].rstrip('\n')
			if temp[0] == 'dns2':
				server_config['dns2'] = temp[1].rstrip('\n')


	for i in range(threads):
		request_handler = Thread(target=handle_request, args=(i, queue, server_config))
		request_handler.setDaemon(True)
		request_handler.start()

	host = server_config.get('host')
	port = server_config.get('port')
	tcp_thread = Thread(target=tcp_connector, args=(host, port))
	tcp_thread.start()
	udp_thread = Thread(target=udp_connector, args=(host, port))
	udp_thread.start()
	queue.join()


if __name__ == "__main__":
	queue = Queue()
	TCP_FLAG = 0
	UDP_FLAG = 1
	TCP_BUFFER = 65535
	UDP_BUFFER = 4096
	logging.config.fileConfig('logging.config')
	logger = logging.getLogger('kiru')
	main()
