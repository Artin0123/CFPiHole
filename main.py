import logging
import pathlib
from typing import List
import requests
import cloudflare
import configparser
import os
import time


class App:
    def __init__(self):
        self.name_prefix = f"[CFPihole]"
        self.logger = logging.getLogger("main")
        self.logger.setLevel(logging.DEBUG)
        # Add console handler if not exists
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        self.whitelist = self.loadWhitelist()

    def loadWhitelist(self):
        return open("whitelist.txt", "r").read().split("\n")

    def run(self):
        config = configparser.ConfigParser()
        config.read("config.ini")
        # check tmp dir
        os.makedirs("./tmp", exist_ok=True)
        all_domains = []
        for list_key in config["Lists"]:
            self.logger.info(f"Setting list {list_key}")
            self.download_file(config["Lists"][list_key], list_key)
            domains = self.convert_to_domain_list(list_key)
            all_domains = all_domains + domains
        # Deduplicate first (preserve original order)
        unique_domains = list(dict.fromkeys(all_domains))
        # Strict-validate and skip invalid domains without attempting to repair
        valid_unique_domains = [d for d in unique_domains if self.is_valid_hostname(d)]
        skipped_count = len(unique_domains) - len(valid_unique_domains)
        if skipped_count > 0:
            self.logger.warning(
                f"Skipping {skipped_count} invalid/unsupported domains (left: {len(valid_unique_domains)})"
            )
        # check if the list is already in Cloudflare
        cf_lists = cloudflare.get_lists(self.name_prefix)
        self.logger.info(f"Number of lists in Cloudflare: {len(cf_lists)}")
        # compare the lists size
        if len(valid_unique_domains) == sum([l["count"] for l in cf_lists]):
            self.logger.warning("Lists are the same size, skipping")
            # Get the gateway policies to check if policy exists
            cf_policies = cloudflare.get_firewall_policies(self.name_prefix)
            self.logger.info(f"Number of policies in Cloudflare: {len(cf_policies)}")
            # If policy exists, we're done
            if len(cf_policies) > 0:
                self.logger.info("Policy already exists, nothing to do")
                return
        else:
            # delete the policy
            cf_policies = cloudflare.get_firewall_policies(self.name_prefix)
            if len(cf_policies) > 0:
                cloudflare.delete_firewall_policy(cf_policies[0]["id"])
            # delete the lists
            for l in cf_lists:
                self.logger.info(f"Deleting list {l['name']}")
                cloudflare.delete_list(l["id"])
                time.sleep(1)
            cf_lists = []
            # chunk the domains into lists of 1000 and create them
            for chunk in self.chunk_list(valid_unique_domains, 1000):
                list_name = f"{self.name_prefix} {len(cf_lists) + 1}"
                self.logger.info(f"Creating list {list_name}")
                _list = cloudflare.create_list(list_name, chunk)
                cf_lists.append(_list)
                time.sleep(1)
        # get the gateway policies
        cf_policies = cloudflare.get_firewall_policies(self.name_prefix)
        self.logger.info(f"Number of policies in Cloudflare: {len(cf_policies)}")
        # setup the gateway policy
        if len(cf_policies) == 0:
            self.logger.info("Creating firewall policy")
            self.logger.debug(f"cf_lists: {cf_lists}")
            if not cf_lists:
                self.logger.error("No lists available to create policy")
                return
            self.logger.debug(f"list_ids: {[l['id'] for l in cf_lists]}")
            cf_policies = cloudflare.create_gateway_policy(
                f"{self.name_prefix} Block Ads", [l["id"] for l in cf_lists]
            )
        elif len(cf_policies) != 1:
            self.logger.error("More than one firewall policy found")
            raise Exception("More than one firewall policy found")
        else:
            self.logger.info("Updating firewall policy")
            cloudflare.update_gateway_policy(
                f"{self.name_prefix} Block Ads",
                cf_policies[0]["id"],
                [l["id"] for l in cf_lists],
            )
        self.logger.info("Done")

    def is_valid_hostname(self, hostname: str) -> bool:
        """
        Strict domain validation without attempting to repair.
        Rules:
        - ASCII only; no spaces or special symbols other than '-' and '.'
        - No trailing or leading dot; no empty labels; no consecutive dots
        - Labels: 1-63 chars, start/end alnum, interior alnum or '-'
        - Total length <= 253
        - TLD must not be all-numeric
        - Require at least one dot (skip single-label like 'localhost')
        - Underscores are not allowed (skip SRV-style names)
        """
        import re

        if not hostname:
            return False
        # Keep original string; do not strip trailing dot – treat as invalid
        s = hostname.strip().lower()

        # Basic character checks
        if any(ord(ch) > 127 for ch in s):
            return False
        # Disallow characters other than a-z, 0-9, '-', '.'
        if not re.fullmatch(r"[a-z0-9\-.]+", s):
            return False
        # No leading/trailing dot, no consecutive dots
        if s.startswith(".") or s.endswith(".") or ".." in s:
            return False
        if len(s) > 253:
            return False

        labels = s.split(".")
        # Require at least one dot
        if len(labels) < 2:
            return False
        label_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
        for lbl in labels:
            # no empty labels
            if not lbl:
                return False
            if not label_re.fullmatch(lbl):
                return False
        # TLD must not be all-numeric
        if re.fullmatch(r"\d+", labels[-1]):
            return False
        return True

    def download_file(self, url, name):
        self.logger.info(f"Downloading file from {url}")
        r = requests.get(url, allow_redirects=True)
        path = pathlib.Path("tmp/" + name)
        open(path, "wb").write(r.content)
        self.logger.info(f"File size: {path.stat().st_size}")

    def convert_to_domain_list(self, file_name: str):
        with open("tmp/" + file_name, "r") as f:
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
                if first_part in [
                    "127.0.0.1",
                    "::1",
                    "0.0.0.0",
                ] or first_part.startswith("127."):
                    is_hosts_file = True
                    break
            # If we find a line that doesn't look like hosts format, break
            break
        self.logger.debug(f"File detected as hosts file: {is_hosts_file}")
        domains = []
        for line in data.splitlines():
            # skip comments and empty lines
            if (
                line.startswith("#")
                or line.startswith(";")
                or line == "\n"
                or line == ""
            ):
                continue
            if is_hosts_file:
                # remove the ip address and the trailing newline
                parts = line.split()
                if len(parts) < 2:
                    continue
                domain = parts[1].strip().lower()
                # skip the localhost entry
                if domain == "localhost":
                    continue
            else:
                domain = line.strip().lower()
            # Check whitelist
            if domain in self.whitelist:
                continue
            domains.append(domain)
        self.logger.info(f"Number of domains: {len(domains)}")
        return domains

    def chunk_list(self, _list: List[str], n: int):
        for i in range(0, len(_list), n):
            yield _list[i : i + n]


if __name__ == "__main__":
    app = App()
    app.run()
