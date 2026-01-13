import os
import time
import logging
import argparse
import requests
import sys


def parse_args():
    parser = argparse.ArgumentParser(
        description="Watch a file and sync its contents to Consul KV"
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Absolute path of the file to watch (must exist)",
    )
    parser.add_argument(
        "--consul-url",
        default="http://localhost:8500",
        help="Consul HTTP address (default: http://localhost:8500)",
    )
    parser.add_argument(
        "--kv-key",
        required=True,
        help="Consul KV key where file content will be stored",
    )
    parser.add_argument(
        "--token",
        required=True,
        help="Consul ACL token (SecretID)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=2,
        help="Polling interval in seconds",
    )
    return parser.parse_args()


def validate_file(path):
    if not os.path.isabs(path):
        logging.error("File path must be absolute: %s", path)
        sys.exit(1)

    if not os.path.isfile(path):
        logging.error("File does not exist: %s", path)
        sys.exit(1)


def validate_consul(consul_url, token):
    try:
        r = requests.get(
            f"{consul_url}/v1/status/leader",
            headers={"X-Consul-Token": token},
            timeout=5,
        )
        if r.status_code != 200:
            logging.error(
                "Consul reachable but returned status %s", r.status_code
            )
            sys.exit(1)
    except Exception as e:
        logging.error("Cannot reach Consul at %s: %s", consul_url, e)
        sys.exit(1)


def read_file(path):
    with open(path, "r") as f:
        return f.read()


def upload_to_consul(consul_url, key, content, token):
    url = f"{consul_url}/v1/kv/{key}"
    headers = {"X-Consul-Token": token}

    r = requests.put(url, data=content.encode("utf-8"), headers=headers)
    if r.status_code != 200:
        logging.error(
            "Failed to write KV %s (status %s): %s",
            key,
            r.status_code,
            r.text,
        )
        return False

    logging.info("Synced file to Consul KV: %s", key)
    return True


def main():
    args = parse_args()

    validate_file(args.file)
    validate_consul(args.consul_url, args.token)

    logging.info("Starting Consul file sync")
    logging.info("Watching file: %s", args.file)
    logging.info("Consul URL: %s", args.consul_url)
    logging.info("KV Key: %s", args.kv_key)

    last_mtime = None
    last_content = None

    while True:
        try:
            stat = os.stat(args.file)

            if last_mtime is None or stat.st_mtime != last_mtime:
                content = read_file(args.file)

                if content != last_content:
                    upload_to_consul(
                        args.consul_url,
                        args.kv_key,
                        content,
                        args.token,
                    )
                    last_content = content

                last_mtime = stat.st_mtime

        except FileNotFoundError:
            logging.error("File disappeared: %s", args.file)
            sys.exit(1)
        except Exception as e:
            logging.error("Unexpected error: %s", e)

        time.sleep(args.interval)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    main()
