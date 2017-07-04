from __future__ import print_function
from threading import Thread
from Queue import Queue
from dnsquery import DNSQuery, Record
import socket, sys, os, logging, logging.config
import dbpool


def tcp_connector(host, port):

	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.bind((host, port))
		sock.listen(5)
		flag = TCP_FLAG

		print("Starting TCP connector on port " + str(port) + "...")

		while True:
			conn, address = sock.accept()
			buf = conn.recv(TCP_BUFFER)
			sock_pair = [conn, address, buf, flag]
			queue.put(sock_pair)

	except socket.error as msg:
		print("Bind failed.  \nError code: " + str(msg[0]) + ' Message ' + msg[1])
		sys.exit()


def udp_connector(host, port):

	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.bind((host, port))
		flag = UDP_FLAG
		print("Starting UDP connector on port " + str(port) + "...")

		while True:
			buf, address = sock.recvfrom(UDP_BUFFER)
			sock_pair = [sock, address, buf, flag]
			queue.put(sock_pair)

	except socket.error as msg:
		print("Bind failed.  \nError code: " + str(msg[0]) + ' Message ' + msg[1])
		sys.exit()


def handle_request(thread_id, q):

	while True:

		sock_pair = q.get()
		sock, address, buf, flag = sock_pair
		query = DNSQuery(thread_id, buf)
		records = query.get_record()

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

		answers = bytearray()

		for record in records:


			#Add C0 0C for message compression

			answers.append(192)
			answers.append(12)

			for key, value in DNSQuery.Q_TYPES.iteritems():
				if value == str(record.type).upper():
					type = int(key)

			answers.append(type >> 8)
			answers.append(type & 255)

			# hardcoding record class to Internet.  No support for Chaos, Hesiod or other unknown class types

			answers.append(0)
			answers.append(1)

			answers.append(record.ttl >> 24)
			answers.append(record.ttl >> 16 & 255)
			answers.append(record.ttl >> 8 & 255)
			answers.append(record.ttl & 255)

			# Encoding for A Record

			if str(record.type).upper() == 'A':
				length = 4
				answers.append(length >> 8)
				answers.append(length & 255)
				ip_list = record.content.split('.')
				for number in ip_list:
					answers.append(int(number))

			# Encoding for CNAME, NS and PTR records

			if str(record.type).upper() == 'CNAME' or str(record.type).upper() == 'NS' or str(record.type).upper() == 'PTR':
				label_list = record.content.split('.')
				if label_list[len(label_list) - 1] == '':
					label_list.pop()

				length = 0
				for label in label_list:
					length += len(label) + 1
				length += 1
				answers.append(length >> 8)
				answers.append(length & 255)
				for label in label_list:
					answers.append(len(label))
					answers.extend(label.encode('ascii'))

				answers.append(0)

			# Encoding for MX record

			if str(record.type).upper() == 'MX':
				label_list = record.content.split('.')
				if label_list[len(label_list) - 1] == '':
					label_list.pop()

				length = 2  # start with 2 bytes for preference
				for label in label_list:
					length += len(label) + 1
				length += 1
				answers.append(length >> 8)
				answers.append(length & 255)
				answers.append(record.priority >> 8)
				answers.append(record.priority & 255)
				for label in label_list:
					answers.append(len(label))
					answers.extend(label.encode('ascii'))

				answers.append(0)

			# Encoding for AAAA record

			if str(record.type).upper() == 'AAAA':
				ip_list = record.content.split(':')
				length = 16
				answers.append(length >> 8)
				answers.append(length & 255)
				for ip in ip_list:
					answers.append(int(ip[:2], 16))
					answers.append(int(ip[2:], 16))

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
				length = 6 # start at 6 bytes
				for label in target_list:
					length += len(label) + 1
				length += 1

				answers.append(length >> 8)
				answers.append(length & 255)
				answers.append(priority >> 8)
				answers.append(priority & 255)
				answers.append(weight >> 8)
				answers.append(weight & 255)
				answers.append(port >> 8)
				answers.append(port & 255)
				for label in target_list:
					answers.append(len(label))
					answers.extend(label.encode('ascii'))
				answers.append(0)

			# Encoding for NAPTR record

			if str(record.type).upper() == 'NAPTR':
				content_list = record.content.split(' ')
				order = int(content_list[0])
				preference = int(content_list[1])
				flags = str(content_list[2])
				services = str(content_list[3])
				regexp = str(content_list[4])
				replace = str(content_list[5])
				replace_list = replace.split('.')
				if replace_list[len(replace_list) - 1] == '':
					replace_list.pop()

				length = 7 + len(services) + len(flags) + len(regexp)
				for label in replace_list:
					length += len(label) + 1
				length += 1
				print("length is " + str(length))
				answers.append(length >> 8)
				answers.append(length & 255)
				answers.append(order >> 8)
				answers.append(order & 255)
				answers.append(preference >> 8)
				answers.append(preference & 255)
				answers.append(len(flags))
				answers.extend(flags.encode('ascii'))
				answers.append(len(services))
				answers.extend(services.encode('ascii'))
				answers.append(len(regexp))
				answers.extend(regexp.encode('ascii'))
				for label in replace_list:
					answers.append(len(label))
					answers.extend(label.encode('ascii'))
				answers.append(0)

		#name_servers = bytearray()
		#additional_records = bytearray()

		response = bytearray()
		response.extend(header)
		response.extend(queries)
		response.extend(answers)

		if logger.level == logging.DEBUG:
			output = query.format_packet(response)
			logger.debug("\nDNS Response:\n" + output)

		if flag == TCP_FLAG:
			sock.send(query.tid)

		else:
			sock.sendto(response, address)
		q.task_done()


def main():

	with open(os.path.join(os.path.dirname(__file__), "config.properties"), 'r') as config:
		for line in config:
			temp = line.split('=')
			if temp[0] == 'threads':
				threads = int(temp[1])
			if temp[0] == 'host':
				host = temp[1].rstrip('\n')
			if temp[0] == 'port':
				port = int(temp[1].rstrip('\n'))


	for i in range(threads):
		request_handler = Thread(target=handle_request, args=(i, queue))
		request_handler.setDaemon(True)
		request_handler.start()

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