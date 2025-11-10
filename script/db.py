# Global vars
WHITELIST_STATUS = 0
BLACKLIST_STATUS = 1

DB_TABLE_INIT_PROXY_LOG = '''CREATE TABLE IF NOT EXISTS proxy_log (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    client_address VARCHAR(15),
    url_hash CHAR(64) NOT NULL,
    url TEXT NOT NULL,
    domain_id INT,
    file_hash CHAR(64) NOT NULL,
    file_size INT NOT NULL,
    tracking_size INT NOT NULL,
    is_javascript TINYINT NOT NULL,
    referer CHAR(64),
    country VARCHAR(8),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domain(id)
);'''

DB_TABLES_INIT_PROXY_STATUS = '''CREATE TABLE IF NOT EXISTS proxy_status (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    requests_intercepted INT NOT NULL DEFAULT 0,
    bytes_intercepted INT NOT NULL DEFAULT 0,
    requests_cleaned INT NOT NULL DEFAULT 0,
    bytes_cleaned INT NOT NULL DEFAULT 0,
    insert_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    update_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);'''

DB_TABLES_INIT_BWLIST = '''CREATE TABLE IF NOT EXISTS bwlist (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    resource_hash CHAR(64) NOT NULL UNIQUE,
    status TINYINT NOT NULL DEFAULT 0,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);'''


def startup_proxy_status(conn):
    insert_query = """
    INSERT INTO proxy_status () VALUES ()
    """
    try:
        cursor = conn.cursor()
        cursor.execute(insert_query)
        conn.commit()
    finally:
        cursor.close()
        conn.close()


def load_whitelist(conn):
    query = """
        SELECT resource_hash FROM bwlist WHERE status = %s; 
    """
    try:
        cursor = conn.cursor()
        cursor.execute(query, (WHITELIST_STATUS,))
        return [element[0] for element in cursor.fetchall()]
    finally:
        cursor.close()
        conn.close()


def load_blacklist(conn):
    query = """
        SELECT resource_hash FROM bwlist WHERE status = %s; 
    """
    try:
        cursor = conn.cursor()
        cursor.execute(query, (BLACKLIST_STATUS,))
        return [element[0] for element in cursor.fetchall()]
    finally:
        cursor.close()
        conn.close()



def store_proxy_log(client_address, url_hash, url, domain_id, file_hash, file_size, tracking_size, is_javascript, referer, country, conn):
    if conn is None:
        return None # Proxy needs to keep running even if database connection is down
    insert_query = """
    INSERT INTO proxy_log (client_address, url_hash, url, domain_id, file_hash, file_size, tracking_size, is_javascript, referer, country)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    data = (client_address, url_hash, url, domain_id, file_hash, file_size, tracking_size, is_javascript, referer, country)
    try:
        cursor = conn.cursor()
        cursor.execute(insert_query, data)
        conn.commit()
    finally:
        cursor.close()
        conn.close()


def get_domain_id(dom_hash, dom_name, conn, pending=1):
    if conn is None:
        return None # Proxy needs to keep running even if database connection is down
    '''
    dom_name: is a first level domain
    If the domain doesnt exist in the database we add it. In cas it does exist, we update the priority to 1.
    '''
    insert_query = """
    INSERT INTO domain (hash, name, pending)
    VALUES (%s, %s, %s)
    ON DUPLICATE KEY UPDATE pending = %s;
    """
    select_query = """
    SELECT id FROM domain WHERE domain.name = %s
    """
    try:
        cursor = conn.cursor()
        cursor.execute(insert_query, (dom_hash, dom_name, pending, pending))
        cursor.execute(select_query, (dom_name,))
        result = cursor.fetchone()[0]
        conn.commit()
        return result if result else None
    finally:
        cursor.close()
        conn.close()

