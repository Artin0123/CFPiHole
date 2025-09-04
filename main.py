import logging
import pathlib
from typing import List
import requests
import cloudflare
import configparser
import pandas as pd
import os
import time
import hashlib  # 新增用於計算哈希

class App:
    def __init__(self):
        self.name_prefix = f"[CFPihole]"
        self.list_name_base = "CFPiHole Domains"
        self.policy_name = "CFPiHole Blocklist Policy"
        self.logger = logging.getLogger("main")
        self.logger.setLevel(logging.DEBUG)
        # Add console handler if not exists
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        self.whitelist = self.loadWhitelist()
        self.last_sizes = {}  # 記錄上次檔案大小

    def loadWhitelist(self):
        return open("whitelist.txt", "r").read().split("\n")

    def run(self):
        config = configparser.ConfigParser()
        config.read('config.ini')
        # check tmp dir
        os.makedirs("./tmp", exist_ok=True)
        all_domains = []
        for list_name in config["Lists"]:  # 改為 list_name 避免覆蓋內建 list
            print("Setting list " + list_name)
            name_prefix = f"[AdBlock-{list_name}]"
            file_path = pathlib.Path("tmp/" + list_name)
            # 檢查檔案是否已存在並比較大小
            if file_path.exists():
                current_size = file_path.stat().st_size
                if list_name in self.last_sizes and self.last_sizes[list_name] == current_size:
                    self.logger.info(f"File {list_name} size unchanged, skipping download")
                    domains = self.convert_to_domain_list(list_name)
                else:
                    self.download_file(config["Lists"][list_name], list_name)
                    domains = self.convert_to_domain_list(list_name)
                    self.last_sizes[list_name] = current_size  # 更新記錄
            else:
                self.download_file(config["Lists"][list_name], list_name)
                domains = self.convert_to_domain_list(list_name)
                self.last_sizes[list_name] = file_path.stat().st_size
            all_domains = all_domains + domains
        unique_domains = pd.unique(pd.Series(all_domains))
        # chunk the domains into lists of 1000
        chunks = list(self.chunk_list(unique_domains, 1000))
        num_chunks = len(chunks)

        # Get existing lists
        cf_lists = cloudflare.get_lists(self.list_name_base)
        self.logger.info(f"Number of existing lists: {len(cf_lists)}")
        self.logger.info(f"Number of needed chunks: {num_chunks}")

        # Get existing policies
        cf_policies = cloudflare.get_firewall_policies(self.policy_name)
        self.logger.info(f"Number of existing policies: {len(cf_policies)}")

        # Record the enabled status of the policy
        policy_enabled = True  # default
        if cf_policies:
            policy_enabled = cf_policies[0]["enabled"]
            self.logger.info(f"Existing policy enabled: {policy_enabled}")

        # Handle lists
        if len(cf_lists) == num_chunks:
            # Update existing lists
            for i, chunk in enumerate(chunks):
                list_name = f"{self.list_name_base} {i+1}"
                existing_list = next((l for l in cf_lists if l["name"] == list_name), None)
                if existing_list:
                    self.logger.info(f"Updating list {list_name}")
                    cloudflare.update_list(existing_list["id"], list_name, chunk)
                    cf_lists[i] = existing_list  # update the list
                else:
                    # If name doesn't match, create new
                    self.logger.info(f"Creating list {list_name}")
                    _list = cloudflare.create_list(list_name, chunk)
                    cf_lists[i] = _list
                time.sleep(1)
        else:
            # Delete existing lists and create new ones
            for l in cf_lists:
                self.logger.info(f"Deleting list {l['name']}")
                cloudflare.delete_list(l["id"])
                time.sleep(1)
            cf_lists = []
            for i, chunk in enumerate(chunks):
                list_name = f"{self.list_name_base} {i+1}"
                self.logger.info(f"Creating list {list_name}")
                _list = cloudflare.create_list(list_name, chunk)
                cf_lists.append(_list)
                time.sleep(1)

        # Handle policy
        if cf_policies:
            # Update existing policy
            self.logger.info("Updating firewall policy")
            cloudflare.update_gateway_policy(
                self.policy_name, cf_policies[0]["id"], [l["id"] for l in cf_lists], policy_enabled)
        else:
            # Create new policy
            self.logger.info("Creating firewall policy")
            if not cf_lists:
                self.logger.error("No lists available to create policy")
                return
            cloudflare.create_gateway_policy(
                self.policy_name, [l["id"] for l in cf_lists], policy_enabled)

        self.logger.info("Done")

    def is_valid_hostname(self, hostname):
        import re
        if len(hostname) > 255:
            return False
        hostname = hostname.rstrip(".")
        allowed = re.compile(
            r'^[a-z0-9]([a-z0-9\-\_]{0,61}[a-z0-9])?$', re.IGNORECASE)
        labels = hostname.split(".")
        # the TLD must not be all-numeric
        if re.match(r"^[0-9]+$", labels[-1]):
            return False
        return all(allowed.match(x) for x in labels)

    def download_file(self, url, name):
        self.logger.info(f"Downloading file from {url}")
        r = requests.get(url, allow_redirects=True)
        path = pathlib.Path("tmp/" + name)
        open(path, "wb").write(r.content)
        self.logger.info(f"File size: {path.stat().st_size}")

    def convert_to_domain_list(self, file_name: str):
        with open("tmp/"+file_name, "r") as f:
            data = f.read()
        # check if the file is a hosts file or a list of domain
        # Only check the first few non-comment lines for hosts file format
        is_hosts_file = False
        lines = data.splitlines()
        for line in lines[:50]:  # Only check first 50 lines
            line = line.strip()
            if line.startswith("#") or line.startswith(";") or line == "":
                continue
            # Check if line starts with an IP address
            parts = line.split()
            if len(parts) >= 2:
                first_part = parts[0]
                if first_part in ["127.0.0.1", "::1", "0.0.0.0"] or first_part.startswith("127."):
                    is_hosts_file = True
                    break
            # If we find a line that doesn't look like hosts format, break
            break
        self.logger.debug(f"File detected as hosts file: {is_hosts_file}")
        domains = []
        for line in data.splitlines():
            # skip comments and empty lines
            if line.startswith("#") or line.startswith(";") or line == "\n" or line == "":
                continue
            if is_hosts_file:
                # remove the ip address and the trailing newline
                parts = line.split()
                if len(parts) < 2:
                    continue
                domain = parts[1].rstrip()
                # skip the localhost entry
                if domain == "localhost":
                    continue
            else:
                domain = line.rstrip()
            # Check whitelist
            if domain in self.whitelist:
                continue
            domains.append(domain)
        self.logger.info(f"Number of domains: {len(domains)}")
        return domains

    def chunk_list(self, _list: List[str], n: int):
        for i in range(0, len(_list), n):
            yield _list[i: i + n]

if __name__ == "__main__":
    app = App()
    app.run()
