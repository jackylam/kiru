from flask import Flask, render_template, g, request, Response, jsonify
import mysql.connector
from mysql.connector import pooling
from record import Record
import os

app = Flask(__name__)

with open(os.path.join(os.path.dirname(__file__),"config.properties"),'r') as config:
	for line in config:
		temp = line.split('=')
		if(temp[0] == 'db_user'):
			db_user = temp[1].rstrip('\n')
		elif(temp[0] == 'db_pass'):
			db_pass = temp[1].rstrip('\n')
		elif(temp[0] == 'db_url'):
			db_url = temp[1].rstrip('\n')
		elif(temp[0] == 'db_name'):
			db_name = temp[1].rstrip('\n')
		else:
			print("Parsing Error")


db = mysql.connector.pooling.MySQLConnectionPool(pool_name = "pool", pool_size=10, autocommit=False, user=db_user, password=db_pass, host=db_url, database=db_name)
print("initialize db connection pool")
conn = db.get_connection()
cursor = conn.cursor()
query = 'SELECT * from user where email = %s and password = %s'
cursor.execute(query,('admin','changeme'))
rs = cursor.fetchall()
cursor.close()
conn.close()


@app.route('/')
def index():
	return render_template("index.html")


@app.route('/login', methods=['POST'])
def login():
	user = request.form['user']
	password = request.form['pass']
	query = 'SELECT active from user where email = %s and password = %s'
	try:
		conn = db.get_connection()
		cursor = conn.cursor()
		cursor.execute(query,(user,password))
		cursor.fetchall()
	except mysql.connector.Error as e:
		print (e)
	finally:
		if cursor.rowcount > 0:
			cursor.close()
			conn.close()
			return render_template("main.html")
		else:
			cursor.close()
			conn.close()
			return render_template("index.html")


@app.route('/api/record', methods=['POST'])
def create_record():
	if ('domain_id' not in request.form or 'name' not in request.form or 'type' not in request.form
		or 'content' not in request.form or 'ttl' not in request.form or 'priority' not in request.form
		or 'change_date' not in request.form or 'disabled' not in request.form or 'order_name' not in request.form
		or 'auth' not in request.form):
		response = jsonify(status="Missing Parameters")
		response.status_code = 400
		return response
	else:
		name = request.form['name']
		id = ''
		domain_id = request.form['domain_id']
		name = request.form['name']
		type = request.form['type']
		content = request.form['content']
		ttl = request.form['ttl']
		priority = request.form['priority']
		change_date = request.form['change_date']
		disabled = request.form['disabled']
		order_name = request.form['order_name']
		auth = request.form['auth']
		data = Record(id, domain_id, name, type, content, ttl, priority, change_date, disabled, order_name, auth)

		success = True
		try:
			conn = db.get_connection()
			cursor = conn.cursor()
			query = 'INSERT into records (domain_id,name,type,content,ttl,priority,change_date,disabled,order_name,auth)  ' \
					'values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
			cursor.execute(query, (domain_id,name,type,content,ttl,priority,change_date,disabled,order_name,auth))
			conn.commit()
		except mysql.connector.Error as e:
			print(e)
			success = False
		finally:
				cursor.close()
				conn.close()
		if success:
			response = Response(response=None,status=200)
		else:
			response = Response(response=None,status=500)
		return response


@app.route('/api/record', methods=['GET'])
def get_record():
	if 'name' in request.args:
		name = request.args['name']
		success = True
		try:
			conn = db.get_connection()
			cursor = conn.cursor()
			query = 'SELECT * FROM records WHERE name = %s'
			cursor.execute(query, (name,))
			rs = cursor.fetchall()
			data_list = []
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
				data = Record(id,domain_id,name,type,content,ttl,priority,change_date,disabled,order_name,auth)
				data_list.append(data)
		except mysql.connector.Error as e:
			print e
			success = False
		finally:
			cursor.close()
			conn.close()
			if success:
				if data_list:
					response = jsonify(status = "OK",record = [temp.serialize() for temp in data_list])
					response.status_code = 200
					return response
				else:
					response = jsonify(status = "Not Found")
					response.status_code = 404
					return response
			else:
				response = jsonify(status = "Database Error")
				response.status_code = 500
				return response
	else:
		response = jsonify(status="Invalid Query String")
		response.status_code = 404
		return response


@app.route('/api/record', methods=['PUT'])
def update_record():
	try:
		success = True
		if 'name' in request.args:
			name = request.args['name']
			conn = db.get_connection()
			cursor = conn.cursor()
			if 'domain_id' in request.form:
				domain_id = request.form['domain_id']
				query = 'UPDATE records set domain_id = %s WHERE name = %s'
				cursor.execute(query, (domain_id, name))
			if 'type' in request.form:
				type = request.form['type']
				query = 'UPDATE records set type = %s WHERE name = %s'
				cursor.execute(query, (type, name))
			if 'content' in request.form:
				content = request.form['content']
				query = 'UPDATE records set content = %s WHERE name = %s'
				cursor.execute(query, (content, name))
			if 'ttl' in request.form:
				ttl = request.form['ttl']
				query = 'UPDATE records set ttl = %s WHERE name = %s'
				cursor.execute(query, (ttl, name))
			if 'priority' in request.form:
				priority = request.form['priority']
				query = 'UPDATE records set priority = %s WHERE name = %s'
				cursor.execute(query, (priority, name))
			if 'change_date' in request.form:
				change_date = request.form['change_date']
				query = 'UPDATE records set change_date = %s WHERE name = %s'
				cursor.execute(query, (change_date, name))
			if 'disabled' in request.form:
				disabled = request.form['disabled']
				query = 'UPDATE records set disabled = %s WHERE name = %s'
				cursor.execute(query, (disabled, name))
			if 'order_name' in request.form:
				order_name = request.form['order_name']
				query = 'UPDATE records set order_name = %s WHERE name = %s'
				cursor.execute(query, (order_name, name))
			if 'auth' in request.form:
				auth = int(request.form['auth'])
				query = 'UPDATE records set auth = %s WHERE name = %s'
				cursor.execute(query, (auth, name))
			conn.commit()
			cursor.close()
		else:
			success = False
	except Exception as e:
		print e
		success = False
	finally:
		conn.close()
		if success:
			response = jsonify(status="OK")
			response.status_code = 200
		else:
			response = jsonify(status="Database Error")
			response.status_code = 500
		return response


@app.route('/api/record', methods=['DELETE'])
def delete_record():
	if 'name' in request.args:
		name = request.args['name']
		try:
			conn = db.get_connection()
			cursor = conn.cursor()
			query = 'DELETE FROM records WHERE name = %s'
			cursor.execute(query, (name,))
			if cursor.rowcount > 0:
				response = jsonify(status = "OK")
				response.status_code = 204
				return response
			else:
				response = jsonify(status = "Not Found")
				response.status_code = 404
				return response
		except mysql.connector.Error as e:
			print e
			response = jsonify(status="Database Error")
			response.status_code = 500
		finally:
			return response
	else:
		response = jsonify(status="Not Found")
		response.status_code = 404
		return response


@app.route('/test')
def test():
	return "test 123"

if __name__ == "__main__":
	app.secret_key = 'E?N?jg47??PNn2?}-?7?'
	app.run(debug=True)
