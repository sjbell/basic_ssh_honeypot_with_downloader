#!/usr/bin/env python
import sys
import os
import traceback
import paramiko
import logging
import redis
import requests
import urllib3
import hashlib
import zipfile
from time import sleep
from urllib.parse import urlparse

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    filename='ssh_honeypot_downloader.log')

# disable InsecureRequestWarnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REDIS_HOST=os.environ.get("REDIS_HOST")
REDIS_PORT=os.environ.get("REDIS_PORT")
REDIS_PASSWORD=os.environ.get("REDIS_PASSWORD")
r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True)

def downloadURL(url):

    # make sure we haven't already checked this URL
    if not r.hexists("checked_urls", url):

        a = urlparse(url)   
        file_name = os.path.basename(a.path)
        logging.info('Downloading URL: '.format(url))
        m_sha256 = hashlib.sha256()
        file_digest = ''
        chunks = []

        try:
            response = requests.get(url, verify=False, timeout=10)

            if response.status_code == 200:
                for data in response.iter_content(8192):
                    m_sha256.update(data)
                    chunks.append(data)

                file_digest = m_sha256.hexdigest()
                directory = "uploaded_files"
                if not os.path.exists(directory):
                    os.makedirs(directory)

                zip_filename = directory+"/"+file_digest+'.zip'

                if not os.path.isfile(zip_filename):
                    file_contents = b''.join(chunks)
                    with zipfile.ZipFile(zip_filename, mode='w') as myzip:
                        myzip.writestr(file_name, file_contents)
                    
            else:
                print("Did not receive http 200 for requested URL. Received: ", response.status_code)
                logging.info('Did not receive http 200 for requested URL. Received {}'.format(response.status_code))

        except Exception as err:
            print('*** Download URL failed: {}'.format(err))
            logging.info('*** Download URL failed: {}'.format(err))
            traceback.print_exc()

        # add url to redis set so we don't check it again (prevents honeypot from becoming a DoS weapon)
        r.hset("checked_urls", url, file_digest)

print("Waiting for URL to download...")
while True:

    try:
        url_to_download = r.lpop("download_queue")
        if url_to_download:
            downloadURL(url_to_download)

    except Exception as err:
        print('*** Download URL failed: {}'.format(err))
        logging.info('*** Download URL failed: {}'.format(err))
        traceback.print_exc()

    sleep(1)
