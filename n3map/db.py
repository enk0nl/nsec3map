import psycopg2
from . import log
from datetime import datetime, timezone
import os

def create_scan(zone, scan_type, zone_type):
    try:
        initiated_by = os.getlogin()
    except OSError:
        initiated_by = ''
    database.cursor.execute('INSERT INTO scans (start_time, initiated_by, zone, scan_type, zone_type) VALUES (%s, %s, %s, %s, %s) RETURNING id', (datetime.now(timezone.utc), initiated_by, zone, scan_type, zone_type))
    database.conn.commit()
    return database.cursor.fetchone()[0]
    
def finish_scan(id, exitcode):
    database.cursor.execute('UPDATE scans SET end_time = %s, exitcode = %s WHERE id = %s', (datetime.now(timezone.utc), exitcode, id))
    database.conn.commit()
    return

def update_zone_type(id, zone_type):
    database.cursor.execute('UPDATE scans SET zone_type = %s WHERE id = %s', (zone_type, id))
    database.conn.commit()
    return

def add_nsec_record(scan_id, owner, next_owner, ttl, cls, types):
    database.cursor.execute('INSERT INTO nsec_resource_records (scan_id, owner, next_owner, ttl, class, types) VALUES (%s, %s, %s, %s, %s, %s)', (scan_id, owner, next_owner, ttl, cls, types))
    database.conn.commit()
    return

def add_nsec3_record(scan_id, owner, hashed_owner, next_hashed_owner, ttl, cls, types):
    database.cursor.execute('INSERT INTO nsec3_resource_records (scan_id, owner, hashed_owner, next_hashed_owner, ttl, class, types) VALUES (%s, %s, %s, %s, %s, %s, %s)', (scan_id, owner, hashed_owner, next_hashed_owner, ttl, cls, types))
    database.conn.commit()
    return

def add_nsec3_parameters(scan_id, hash_algorithm, flags, iterations, salt):
    database.cursor.execute('INSERT INTO nsec3_parameters (scan_id, hash_algorithm, flags, iterations, salt) VALUES (%s, %s, %s, %s, %s)', (scan_id, hash_algorithm, flags, iterations, salt))
    database.conn.commit()
    database.parameters_written = True
    return

def add_log(scan_id, severity, message):
    database.cursor.execute('INSERT INTO logs (scan_id, message, severity) VALUES (%s, %s, %s)', (scan_id, message, severity))
    database.conn.commit()
    return

class Database(object):
    def __init__(self,
                 database,
                 host,
                 user,
                 password,
                 port):
        self.database = database
        self.host = host
        self.user = user
        self.password = password
        self.port = port

    def connect(self):
        log.info('connecting to database: ', self.host, ':', self.port, '/', self.database, ' as ', self.user)
        try:
            self.conn = psycopg2.connect(database=self.database,
                                        host=self.host,
                                        user=self.user,
                                        password=self.password,
                                        port=self.port)
        except psycopg2.OperationalError as e:
                log.fatal('unable to connect to database: ', str(e))

        self.cursor = self.conn.cursor()

    def close(self):
        self.conn.close()

    def init(self):
        try:
            self.cursor.execute('''
                CREATE TABLE scans (
                    id SERIAL PRIMARY KEY,
                    start_time TIMESTAMP NOT NULL,
                    end_time TIMESTAMP,
                    initiated_by VARCHAR(255),
                    zone VARCHAR(255) NOT NULL,
                    scan_type VARCHAR(50),
                    zone_type VARCHAR(50),
                    exitcode VARCHAR(10)
                );

                CREATE TABLE nsec_resource_records (
                    id SERIAL PRIMARY KEY,
                    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
                    owner VARCHAR(255),
                    next_owner VARCHAR(255),
                    ttl INTEGER,
                    class VARCHAR(10),
                    types VARCHAR(255),
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE nsec3_resource_records (
                    id SERIAL PRIMARY KEY,
                    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
                    owner VARCHAR(255) NOT NULL,
                    hashed_owner VARCHAR(255) NOT NULL,
                    next_hashed_owner VARCHAR(255),
                    ttl INTEGER,
                    class VARCHAR(10),
                    types VARCHAR(255),
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE nsec3_parameters (
                    id SERIAL PRIMARY KEY,
                    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
                    hash_algorithm INTEGER,
                    flags INTEGER,
                    iterations INTEGER,
                    salt VARCHAR(255)
                );

                CREATE TABLE logs (
                    id SERIAL PRIMARY KEY,
                    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    message TEXT,
                    severity VARCHAR(20) CHECK (severity IN ('INFO', 'WARNING', 'ERROR', 'CRITICAL'))
                );
            ''')
            self.conn.commit()
            return
        except psycopg2.errors.DuplicateTable as e:
            log.fatal('unable to initialize database: ', str(e))
    
