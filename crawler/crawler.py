#!/usr/bin/python

import requests

def request(url):
	try:
		return requests.get("http://" + url)
	except requests.exceptions.ConnectionError:
		pass

path=[]

def dir_discover(url):
	with open("common_directories.txt","r") as wordlist_file:
		for line in wordlist_file:
			common_dir = line.strip()
			test_url = url + "/" + common_dir
			response = request(test_url)
			if response :
				print("[+] Discovered URL >> " + test_url)
				path.append(common_dir)

#Input in URL want to scan
url=""

dir_discover(url)

for paths in path:
	dir_discover(url + "/" + paths)
