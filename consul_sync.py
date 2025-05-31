import os
import time
import logging
import requests

# CONFIGURATION
FILE_TO_WATCH = "./ssh-ca/id_rsa.pub"
CONSUL_URL = "http://localhost:8500"
CONSUL_KV_KEY = "ca/pub-key/id_rsa.pub"  # Consul KV key where content will be stored
CONSUL_TOKEN = "19713bd9-273e-2377-ba52-228b7b5b136e"  # Your token here

POLL_INTERVAL = 2  # seconds to wait between file checks

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def read_file_content(path):
    try:
        with open(path, "r") as f:
            return f.read()
    except Exception as e:
        logging.error(f"Failed to read file {path}: {e}")
        return None

def upload_to_consul(key, value):
    url = f"{CONSUL_URL}/v1/kv/{key}"
    headers = {"X-Consul-Token": CONSUL_TOKEN} if CONSUL_TOKEN else {}
    try:
        response = requests.put(url, data=value.encode("utf-8"), headers=headers)
        if response.status_code == 200:
            logging.info(f"Uploaded to Consul KV: {key}")
        else:
            logging.error(f"Failed to upload to Consul KV: status {response.status_code}, response {response.text}")
    except Exception as e:
        logging.error(f"Exception during upload to Consul: {e}")

def main():
    if not os.path.isfile(FILE_TO_WATCH):
        logging.error(f"File not found: {FILE_TO_WATCH}")
        return

    last_modified = None
    last_content = None

    logging.info(f"Watching file: {FILE_TO_WATCH} for changes...")

    while True:
        try:
            stat = os.stat(FILE_TO_WATCH)
            if last_modified is None or stat.st_mtime != last_modified:
                content = read_file_content(FILE_TO_WATCH)
                if content is not None and content != last_content:
                    upload_to_consul(CONSUL_KV_KEY, content)
                    last_content = content
                last_modified = stat.st_mtime
        except FileNotFoundError:
            logging.warning(f"File disappeared: {FILE_TO_WATCH}")
            last_modified = None
            last_content = None
        except Exception as e:
            logging.error(f"Error watching file: {e}")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()

