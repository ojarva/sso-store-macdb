"""
MAC-IP database.

Firewalls/routers post output of "arp -an", which is then parsed. 
For each MAC address, session is automatically opened and closed
when MAC appears/disapppears from the firewall.

For added accuracy, when mac address with open session is posted,
last seen timestamp is updated.

"""
import random
import redis
import time
import datetime
import re
from config import Config
from mac_db_parser import MacDbParser
from instrumentation import *
import _mysql

class MacDbUpdate:
    """ Handles mac database updates posted by firewalls. """
    def __init__(self, server_hostname):
        self._db = None
        self.server_hostname = server_hostname
        self.config = Config()
        self.redis = redis.Redis(host=self.config.get("redis-hostname"),
                     port=self.config.get("redis-port"),
                     db=self.config.get("redis-db"))

    @property
    def db(self):
        """ Returns (cached) mysql instance """
        if self._db:
            return self._db
        self._db = _mysql.connect(self.config.get("mysql-hostname"), 
                                 self.config.get("mysql-username"), 
                                 self.config.get("mysql-password"), 
                                 self.config.get("mysql-database"))
        return self._db
        
        
    @classmethod
    def _escape(cls, string):
        """ Crappy workaround to escape MySQL query parameters """
        if string is None:
            return "null"
        return "'"+_mysql.escape_string(str(string))+"'"
        
    @classmethod
    def escape(cls, items):
        """ If items is list, returns escaped list of MySQL query
            parameters. Otherwise, escaped string """
        if isinstance(items, list):
            return [cls._escape(item) for item in items]
        return cls._escape(items)

    def open_session(self, ip_addr, mac, start_time, end_time=None):
        """ New mac address is available. Open a new session. 
            Closes old sessions. """
        statsd.incr("mac.update.session.open")

        now = datetime.datetime.now()

        self.db.query("UPDATE macdb SET end_time=%s WHERE ip=%s and server_hostname=%s and end_time is NULL" % tuple(self.escape([now, ip_addr, self.server_hostname])))
        self.db.store_result()
        self.db.query("UPDATE macdb SET end_time=%s WHERE mac=%s and server_hostname=%s and end_time is NULL" % tuple(self.escape([now, mac, self.server_hostname])))
        self.db.store_result()
        self.db.query("INSERT INTO macdb VALUES (%s,%s,%s,%s,%s,%s)" % tuple(self.escape([mac, ip_addr, self.server_hostname, start_time, end_time, now])))
        self.db.store_result()
        self.redis.rpush("ip-resolve-queue", ip_addr)

    def close_session(self, ip_addr, mac, end_time=None):
        """ When mac is not available anymore, close the session(s)"""
        statsd.incr("mac.update.session.close")
        now = datetime.datetime.now()
        if end_time is None:
            end_time = now
        self.db.query("UPDATE macdb SET end_time=%s WHERE ip=%s and server_hostname=%s and end_time is NULL" % tuple(self.escape([now, ip_addr, self.server_hostname])))
        self.db.store_result()
        self.db.query("UPDATE macdb SET end_time=%s WHERE mac=%s and server_hostname=%s and end_time is NULL" % tuple(self.escape([now, mac, self.server_hostname])))
        self.db.store_result()

    def update_session(self, ip_addr, mac):
        """ Update session timestamp """
        now = datetime.datetime.now()
        redis_key_prefix = "macdb-update-tmp-%s-%s-%s-" % (self.server_hostname, ip_addr, mac)
        last_update = self.redis.get(redis_key_prefix+"last_update")
        if last_update:
            last_update = float(last_update)
        else:
            last_update = 0
        if random.random() < 0.18 or time.time() - last_update > 120 + random.random() * 20:
            statsd.incr("mac.update.session.update")
            self.db.query("UPDATE macdb SET known_connected=%s WHERE ip=%s and mac=%s and server_hostname=%s" % tuple(self.escape([now, ip_addr, mac, self.server_hostname])))
            self.db.store_result()
            self.redis.delete(redis_key_prefix+"known_connected")
            self.redis.set(redis_key_prefix+"last_update", time.time())
        else:
            statsd.incr("mac.update.session.postpone_update")
            self.redis.mset({
                 redis_key_prefix+"known_connected": now})

    def update(self, details):
        """ Update a session. Opens a new session if session does not exist."""
        statsd.incr("mac.update.update")
        ip_addr = details["ip"]
        mac = details["mac"]
        redis_key = "macdb-connected-%s" % self.server_hostname
        redis_val ="%s_%s" % (ip_addr, mac)

        if not self.redis.sismember(redis_key, redis_val):
            # Not connected. Open a new session.
            self.open_session(ip_addr, mac, datetime.datetime.now())
        else:
            # Update known timestamp
            self.update_session(ip_addr, mac)

        self.redis.sadd(redis_key+"-tmp", redis_val)

    def finish(self):
        """ Must be called at the end of processing for cleanup """
        cdb_key = "macdb-connected-%s" % self.server_hostname
        if not self.redis.exists(cdb_key):
            # No old key exists. First run.
            if self.redis.exists(cdb_key+"-tmp"):
                # New one exists. Rename.
                # As no old key exists, there is no sessions to close.
                self.redis.rename(cdb_key+"-tmp", cdb_key)
        else:
            # old entries exists.
            if self.redis.exists(cdb_key+"-tmp"):
                # Both new and old entries exist. Close disappeared sessions.
                disappeared_macs = self.redis.sdiff(cdb_key, cdb_key+"-tmp")
                for ip_mac in disappeared_macs:
                    ip_addr, mac = ip_mac.split("_")
                    self.close_session(ip_addr, mac)

                self.redis.rename(cdb_key+"-tmp", cdb_key)
            else:
                # Run with old entries, but without any new entries.
                # Close all connections and delete old data.
                old_macs = self.redis.smembers(cdb_key)
                for ip_mac in old_macs:
                    ip_addr, mac = ip_mac.split("_")
                    self.close_session(ip_addr, mac)
                self.redis.delete(cdb_key)


def is_valid_hostname(hostname):
    """ Validates hostname. From http://stackoverflow.com/a/2532344/592174 """
    if len(hostname) > 255:
        return False
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

@timing("mac.update.main")
def application(environ, start_response):
    """ WSGI worker """
    statsd.incr("mac.update.main.counter")
    start_response("200 OK", [("Content-Type", "text/plain")])
    query_string = environ["QUERY_STRING"]
    query_string = query_string.split("&")
    hostname = False
    for item in query_string:
        item = item.split("=")
        if len(item) == 2:
            if item[0] == "server":
                if is_valid_hostname(item[1]):
                    hostname = item[1]
    if not hostname:
        return ["Invalid hostname"]

    macdb_update = MacDbUpdate(hostname)
    macs = MacDbParser(environ["wsgi.input"])
    for mac in macs.entries:
        if mac["mac"] == "(incomplete)":
            continue
        macdb_update.update(mac)
    macdb_update.finish()
    
    return [str(macs.entries)]
