import os
import time
import logging
import requests
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Watch a file and upload its contents to Consul KV store.")
    parser.add_argument("--file", default="./ssh-ca/id_rsa.pub", help="Path of file to watch")
    parser.add_argument("--consul-url", default="http://localhost:8500", help="Consul server URL")
    parser.add_argument("--kv-key", default="ca/pub-key/id_rsa.pub", help="Consul KV key to store the file content")
    parser.add_argument("--token", default=None, help="Consul ACL token")
    parser.add_argument("--interval", type=int, default=2, help="Polling interval in seconds")
    return parser.parse_args()

def read_file_content(path):
    try:
        with open(path, "r") as f:
            return f.read()
    except Exception as e:
        logging.error(f"Failed to read file {path}: {e}")
        return None

def upload_to_consul(url, key, value, token):
    full_url = f"{url}/v1/kv/{key}"
    headers = {"X-Consul-Token": token} if token else {}
    try:
        response = requests.put(full_url, data=value.encode("utf-8"), headers=headers)
        if response.status_code == 200:
            logging.info(f"Uploaded to Consul KV: {key}")
        else:
            logging.error(f"Failed to upload to Consul KV: status {response.status_code}, response {response.text}")
    except Exception as e:
        logging.error(f"Exception during upload to Consul: {e}")

def main():
    args = parse_args()

    if not os.path.isfile(args.file):
        logging.error(f"File not found: {args.file}")
        return

    last_modified = None
    last_content = None

    logging.info(f"Watching file: {args.file} for changes...")

    while True:
        try:
            stat = os.stat(args.file)
            if last_modified is None or stat.st_mtime != last_modified:
                content = read_file_content(args.file)
                if content is not None and content != last_content:
                    upload_to_consul(args.consul_url, args.kv_key, content, args.token)
                    last_content = content
                last_modified = stat.st_mtime
        except FileNotFoundError:
            logging.warning(f"File disappeared: {args.file}")
            last_modified = None
            last_content = None
        except Exception as e:
            logging.error(f"Error watching file: {e}")

        time.sleep(args.interval)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    main()

