#!/usr/bin/python

import scanner

target_url = "url"
links_to_ignore = ["url/logout.php"]

data_dict = {"username": "admin", "password": "password", "Login": "submit"}

vuln_scanner = scanner.Scanner(target_url, links_to_ignore)
vuln_scanner.session.post("url/login.php", data=data_dict)

vuln_scanner.crawl()
vuln_scanner.run_scanner()