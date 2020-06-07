import sys, os, logging, logging.config
import mariadb

logging.config.fileConfig('logging.config')
logger = logging.getLogger('dbpool')


def create_pool():
    with open(os.path.join(os.path.dirname(__file__), "config.properties"), 'r') as config:
        for line in config:
            temp = line.split('=')
            if temp[0] == 'db_user':
                db_user = temp[1].rstrip('\n')
            if temp[0] == 'db_pass':
                db_pass = temp[1].rstrip('\n')
            if temp[0] == 'db_url':
                db_url = temp[1].rstrip('\n')
            if temp[0] == 'db_name':
                db_name = temp[1].rstrip('\n')
            if temp[0] == 'db_size':
                db_size = int(temp[1].rstrip('\n'))

    db = mariadb.ConnectionPool(user=db_user, password=db_pass, host=db_url, port=3306, pool_name=db_name,
								pool_size=db_size, database=db_name)
    logger.info("\ninitialize db connection pool...")
    conn = db.get_connection()
    cursor = conn.cursor()
    query = 'SELECT VERSION()'
    cursor.execute(query)
    rs = cursor.fetchone()
    if rs is not None:
        logger.info("\ndb connection pool initialized\ndb version = %s\npool size = %d", rs[0], db.pool_size)
    cursor.close()
    conn.close()
    return db


def get_database():
    global db
    if not isinstance(db, mariadb.ConnectionPool):
        db = create_pool()
        return db
    else:
        return db
# Initialize database pool on import
db = create_pool()
