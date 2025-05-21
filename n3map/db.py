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
                                
                CREATE INDEX idx_nsec_resource_records_scan_id ON nsec_resource_records (scan_id);
                CREATE INDEX idx_nsec3_resource_records_scan_id ON nsec3_resource_records (scan_id);
                CREATE INDEX idx_nsec3_parameters_scan_id ON nsec3_parameters (scan_id);
                CREATE INDEX idx_logs_scan_id ON logs (scan_id);

                CREATE MATERIALIZED VIEW domains_all AS SELECT DISTINCT REGEXP_REPLACE(zone, '\\.$', '') AS domain FROM scans;
                CREATE INDEX idx_domains_all_domain ON domains_all(domain);
                CREATE MATERIALIZED VIEW domains_unknown AS SELECT DISTINCT REGEXP_REPLACE(zone, '\\.$', '') AS domain FROM scans WHERE zone_type = 'unknown';
                CREATE INDEX idx_domains_unknown_domain ON domains_unknown(domain);
                CREATE MATERIALIZED VIEW domains_no_dnssec AS SELECT DISTINCT REGEXP_REPLACE(zone, '\\.$', '') AS domain FROM scans WHERE zone_type = 'no_dnssec';
                CREATE INDEX idx_domains_no_dnssec_domain ON domains_no_dnssec(domain);
                CREATE MATERIALIZED VIEW domains_nsec AS SELECT DISTINCT REGEXP_REPLACE(zone, '\\.$', '') AS domain FROM scans WHERE zone_type = 'nsec';
                CREATE INDEX idx_domains_nsec_domain ON domains_nsec(domain);
                CREATE MATERIALIZED VIEW domains_nsec3 AS SELECT DISTINCT REGEXP_REPLACE(zone, '\\.$', '') AS domain FROM scans WHERE zone_type = 'nsec3';
                CREATE INDEX idx_domains_nsec3_domain ON domains_nsec3(domain);
                
                CREATE MATERIALIZED VIEW domains_nsec_lies AS SELECT DISTINCT REGEXP_REPLACE(zone, '\\.$', '') AS domain FROM scans WHERE zone_type = 'nsec' AND id IN (
                    SELECT DISTINCT scan_id FROM logs WHERE message LIKE '%nsone.net%' OR message LIKE '%cloudflare.com%' OR message LIKE '%awsdns%');
                CREATE INDEX idx_domains_nsec_lies ON domains_nsec_lies(domain);
                CREATE MATERIALIZED VIEW domains_nsec3_lies AS SELECT DISTINCT REGEXP_REPLACE(zone, '\\.$', '') AS domain FROM scans WHERE zone_type = 'nsec3' AND id IN (
                    SELECT DISTINCT scan_id FROM logs WHERE message LIKE '%nsone.net%' OR message LIKE '%cloudflare.com%' OR message LIKE '%awsdns%');
                CREATE INDEX idx_domains_nsec3_lies ON domains_nsec3_lies(domain);
                CREATE MATERIALIZED VIEW domains_nsec_avoid_lies AS SELECT * FROM domains_nsec WHERE domain NOT IN (SELECT domain from domains_nsec_lies);
                CREATE INDEX idx_domains_nsec_avoid_lies ON domains_nsec_avoid_lies(domain);
                CREATE MATERIALIZED VIEW domains_nsec3_avoid_lies AS SELECT * FROM domains_nsec3 WHERE domain NOT IN (SELECT domain from domains_nsec3_lies);
                CREATE INDEX idx_domains_nsec3_avoid_lies ON domains_nsec3_avoid_lies(domain);

                CREATE VIEW stats_total_scans AS SELECT COUNT(id) from scans;
                CREATE VIEW stats_total_nsec_scans AS SELECT COUNT(*) FROM scans WHERE scan_type = 'nsec';
                CREATE VIEW stats_nsec_zones_walked AS SELECT COUNT(DISTINCT zone) FROM scans WHERE scan_type = 'nsec' OR (scan_type = 'auto' AND 'zone_type' = 'nsec');
                CREATE VIEW stats_nsec3_zones_walked AS SELECT COUNT(DISTINCT zone) FROM scans WHERE scan_type = 'nsec3' OR (scan_type = 'auto' AND 'zone_type' = 'nsec3');
                CREATE VIEW stats_total_zones_walked AS SELECT COUNT(DISTINCT zone) FROM scans WHERE scan_type = 'nsec' OR scan_type = 'nsec3' OR (scan_type = 'auto' AND ('zone_type' = 'nsec3' OR 'zone_type' = 'nsec'));

                CREATE VIEW stats_total_scans_by_zone_type AS SELECT zone_type,COUNT(id) FROM scans
                    GROUP BY zone_type
                    ORDER BY
                        CASE zone_type
                            WHEN 'nsec3' THEN 1
                            WHEN 'nsec' THEN 2
                            WHEN 'no_dnssec' THEN 3
                            WHEN 'unknown' THEN 4
                            ELSE 5
                        END;

                CREATE VIEW stats_total_domains AS SELECT COUNT(DISTINCT zone) FROM scans;
                
                CREATE VIEW stats_domains_by_zone_type AS
                    WITH ranked_domains AS (
                        SELECT
                            zone,
                            zone_type,
                            ROW_NUMBER() OVER (
                                PARTITION BY zone
                                ORDER BY
                                    CASE zone_type
                                        WHEN 'nsec3' THEN 1
                                        WHEN 'nsec' THEN 2
                                        WHEN 'no_dnssec' THEN 3
                                        WHEN 'unknown' THEN 4
                                        ELSE 5
                                    END
                            ) AS rn
                        FROM scans
                    ),
                    highest_precedence AS (
                        SELECT zone, zone_type
                        FROM ranked_domains
                        WHERE rn = 1
                    )
                    SELECT zone_type, COUNT(*)
                    FROM highest_precedence
                    GROUP BY zone_type
                    ORDER BY
                        CASE zone_type
                            WHEN 'nsec3' THEN 1
                            WHEN 'nsec' THEN 2
                            WHEN 'no_dnssec' THEN 3
                            WHEN 'unknown' THEN 4
                            ELSE 5
                        END;
                
                CREATE MATERIALIZED VIEW subdomains_all_by_owner AS SELECT
                    d.owner,
                    subs[i] AS subdomain
                FROM (
                    SELECT DISTINCT owner
                    FROM nsec_resource_records
                ) d
                CROSS JOIN LATERAL (
                    SELECT string_to_array(d.owner, '.') AS full_parts
                ) p
                CROSS JOIN LATERAL (
                    SELECT p.full_parts[1:array_length(p.full_parts, 1) - 3] AS subs
                ) sliced
                CROSS JOIN LATERAL generate_subscripts(sliced.subs, 1) AS gs(i);

                CREATE MATERIALIZED VIEW subdomains_a_aaaa_by_owner AS SELECT 
                    d.owner,
                    subs[i] AS subdomain
                FROM (
                    SELECT DISTINCT owner
                    FROM nsec_resource_records
                    WHERE (
                        types LIKE '{A%'
                        OR types LIKE '%,A%'
                        OR types LIKE '{AAAA%'
                        OR types LIKE '%,AAAA%'
                    )
                ) d
                CROSS JOIN LATERAL (
                    SELECT string_to_array(d.owner, '.') AS full_parts
                ) p
                CROSS JOIN LATERAL (
                    SELECT p.full_parts[1:array_length(p.full_parts, 1) - 3] AS subs
                ) sliced
                CROSS JOIN LATERAL generate_subscripts(sliced.subs, 1) AS gs(i);

                CREATE VIEW subdomains_all_by_occurrance AS
                SELECT
                    subdomain,
                    COUNT(*)
                FROM subdomains_all_by_owner
                GROUP BY subdomain
                ORDER BY count DESC, subdomain;

                CREATE VIEW subdomains_a_aaaa_by_occurrance AS
                SELECT
                    subdomain,
                    COUNT(*)
                FROM subdomains_a_aaaa_by_owner
                GROUP BY subdomain
                ORDER BY count DESC, subdomain;
                
                CREATE VIEW stats_total_owners AS SELECT COUNT(DISTINCT OWNER) FROM nsec_resource_records;
                CREATE VIEW stats_total_subdomains AS SELECT COUNT(*) FROM subdomains_all_by_occurrance;
                
                CREATE MATERIALIZED VIEW nameservers_black_lies AS
                SELECT DISTINCT
                    TRIM(
                        TRAILING '.' FROM
                        SUBSTRING(message FROM '\\(([^\\s)]+(?:\\.[^\\s)]+)+)')
                    ) AS nameserver
                FROM logs
                WHERE message LIKE '%nameserver:%'
                    AND scan_id IN (
                        SELECT DISTINCT scan_id
                        FROM logs
                        WHERE message LIKE '%black lies%'
                    );
            ''')
            self.conn.commit()
            return
        except psycopg2.errors.DuplicateTable as e:
            log.fatal('unable to initialize database: ', str(e))

