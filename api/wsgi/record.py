class Record:

	def __init__(self,id,domain_id,name,type,content,ttl,priority,change_date,disabled,order_name,auth):
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
