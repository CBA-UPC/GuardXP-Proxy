import os
import sys
import time
import json
import logging
import geoip2.database
import mysql.connector

from time import gmtime, strftime
from dotenv import load_dotenv
from hashlib import sha256
from mitmproxy import http
from tld.utils import update_tld_names
from tld import get_fld

from utils import load_list, get_replacement, truncate_url, get_domain, is_base_domain
from db import (
    DB_TABLE_INIT_PROXY_LOG, 
    DB_TABLES_INIT_PROXY_STATUS, 
    DB_TABLES_INIT_BWLIST,
    startup_proxy_status,
    store_proxy_log, 
    get_domain_id,
    load_whitelist,
    load_blacklist
)

load_dotenv()

DEBUG = os.getenv("GUARDXP_DEBUG")

DOCKER_VOL_PATH = "/home/mitmproxy/.mitmproxy/"
GEOIP2_DB_PATH = os.path.join(DOCKER_VOL_PATH, "geoip2_db", "GeoLite2-Country.mmdb")
# TODO: Upload offset list in public repo and retrieve it from there.
OFFSET_LISTS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../offsets/offsets.json")

db_config = {
    "host": os.getenv("DB_HOST"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"),
    "database": os.getenv("DB_NAME"),
    "collation": "utf8mb4_general_ci",
}

try:
    pool = mysql.connector.pooling.MySQLConnectionPool(pool_name="mypool", pool_size=5, **db_config)
except mysql.connector.Error as err:
    logging.critical(f"Failed to initialize connection pool: {err}")
    sys.exit(1)

def get_connection():
    for attempt in range(2):
        try:
            conn = pool.get_connection()
            conn.ping(reconnect=True, attempts=1, delay=1)
            return conn
        except mysql.connector.Error as err:
            logging.error(f"Database connection error (attempt {attempt+1}): {err}")
            if attempt > 0:
                logging.error("Database connection failed twice. Continuing without DB.")
                return None


if DEBUG:
    conn = get_connection()
    if conn is not None:
        cursor = conn.cursor()
        try:
            cursor.execute(DB_TABLE_INIT_PROXY_LOG)
            conn.commit()
            cursor.execute(DB_TABLES_INIT_PROXY_STATUS)
            conn.commit()
            cursor.execute(DB_TABLES_INIT_BWLIST)
            conn.commit()
        finally:
            cursor.close()
            conn.close() # Doesn't kill the connection, it returns it to the pool



class ASTrack:
    def __init__(self):
        try:
            self.offsets = self.load_offsets(OFFSET_LISTS_PATH)
            logging.info(f"[ASTrack] Loaded offset list with {len(self.offsets)} entries.")
            self.whitelist = load_whitelist(conn=get_connection())
            logging.info(f"Whitelist content -> {self.whitelist}")
            self.blacklist = load_blacklist(conn=get_connection())
            logging.info(f"Blacklist content -> {self.blacklist}")
            self.last_update = time.time()
            # update_tld_names() # fails inside docker
            self.geodb_reader = geoip2.database.Reader(GEOIP2_DB_PATH)
            startup_proxy_status(conn=get_connection())
        except Exception as e:
            logging.critical(f"Startup process failed: {e}")
            sys.exit(1)

    def proxy_update(self):
        logging.info("Running list content update...")
        try:
            self.whitelist = load_whitelist(conn=get_connection())
            logging.info(f"Whitelist content -> {self.whitelist}")
            self.blacklist = load_blacklist(conn=get_connection())
            logging.info(f"Blacklist content -> {self.blacklist}")
            logging.info("List content update success.")
        except Exception as e:
            logging.error("Failed to update lists content!")

    def load_offsets(self, path):
        '''
        Load offset list from path.
        '''
        with open(path, 'r') as file:
            content = file.read()
        return json.loads(content)

    def clean_resource(self, content_bytes, tracking_parts):
        '''
        Remove the sections specified in tracking_parts (list[(offset, length)]) from content_bytes.
        '''
        clean_content = bytearray()
        try:
            index = 0
            for offset, length in tracking_parts:
                clean_part = content_bytes[index:offset]
                clean_content.extend(clean_part)
                index = offset + length
            clean_content.extend(content_bytes[index:])
        except Exception as e:
            # In case the list is malformed and causes cleaning process to break
            clean_content = b''
        return bytes(clean_content)

    def response(self, flow: http.HTTPFlow):
        '''
        Intercepts and analyzes response events to clean tracking code classified by ASTrack.
        '''
        if DEBUG:
            # Try to diable caching -- For testing purposes
            flow.response.headers["expires"] = "Fri, 01 Jan 1990 00:00:00 GMT"
            flow.response.headers["last-modified"] = strftime("%a, %d %b %Y %H:%M:%S %Z", gmtime())
            flow.response.headers["cache-control"] = "max-age=0, no-cache, no-store, must-revalidate, proxy-revalidate"

        # Check if we need to update the lists: Inefficient but is the most simple way
        current_time = time.time()
        if current_time - self.last_update > 15:
            self.proxy_update()
            self.last_update = current_time

        original_size = len(flow.response.content)
        filtered = False

        # [ Execute ASTrack checks ] > All responses
        content_hash = sha256(flow.response.content).hexdigest()

        # Ignore resources that are whitelisted
        if content_hash not in self.whitelist:
            # Completely remove content of blacklisted resources
            if content_hash in self.blacklist:
                flow.response.content = b''
                filtered = True
            # Pass through ASTrack filter in any other case
            else:
                replacement_entry = self.offsets.get(content_hash, None)  # More efficient, returns None if not found 
                if replacement_entry is not None:
                    # TODO: review if the offset list kind of whitelist/blacklist is needed, as there arent any cases with current offset list
                    # Resources tagged -1 -> blacklisted, resources tagged 0 -> whitelisted
                    if replacement_entry["num"] != 0:
                        filtered = True
                        if replacement_entry["num"] == -1:
                            flow.response.content = b''
                        else:
                            flow.response.content = self.clean_resource(flow.response.content, replacement_entry["parts"])
        
        replacement_size = len(flow.response.content)

        # Try to identify which domain is sending the request
        origin_header = flow.request.headers["Origin"] if "Origin" in flow.request.headers else None
        referer_header = flow.request.headers["Referer"] if "Referer" in flow.request.headers else None
        referer = referer_header if referer_header is not None else origin_header

        # Check if requested url is a base domain to add it to the proxy_domain table.
        domain_id = None
        is_base, _ = is_base_domain(flow.request.url)
        if is_base:
            domain_name = get_fld(flow.request.url)
            domain_hash = sha256(domain_name.encode()).hexdigest()
            domain_id = get_domain_id(domain_hash, domain_name, conn=get_connection()) # adds domain to table
        
        # Get country code for all base domains or cleaned resources
        country_code = None
        if is_base or filtered:
            # GeoIP location and country code request
            # TODO: Maybe do it for all requests, not only requests to base domains
            if flow.server_conn.timestamp_start is not None:
                server_ip = flow.server_conn.ip_address[0]
                try:
                    res = self.geodb_reader.country(server_ip)
                    country_code = res.registered_country.iso_code if res.registered_country is not None else res.country.iso_code
                except Exception as e:
                    logging.warn(f"geoip2 couldn't find location for {server_ip}")
                    pass  # :D

        if filtered:
            self.resource_log(flow.request.url, referer, content_hash, original_size, replacement_size)

        store_proxy_log(
                        client_address = flow.client_conn.address[0],
                        url_hash       = sha256(flow.request.url.encode()).hexdigest(),
                        url            = flow.request.url,
                        domain_id      = domain_id,
                        file_hash      = content_hash,
                        file_size      = original_size,
                        tracking_size  = original_size-replacement_size,
                        is_javascript  = int((flow.request.url).lower().endswith(".js")),
                        referer        = sha256(referer.encode()).hexdigest() if referer is not None else referer,
                        country        = country_code,
                        conn=get_connection()
                        )

    def resource_log(self, url, referer, hash, original_size, replacement_size):
        logging.warn(f"[ASTrack] Tracking Resource " + '\n'
                     + f"    url: {url}\n"
                     + f"    referer: {referer}\n"
                     + f"    hash: {hash}\n"
                     + f"    size (bytes): {original_size} -> {replacement_size}\n")

addons = [ASTrack()]

