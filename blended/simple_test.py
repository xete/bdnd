#!/usr/bin/env python

from baidupcsapi import PCS
import os

username = raw_input('username: ')
os.system('stty -echo')
password = raw_input('password: ')
os.system('stty echo')

pcs = PCS(username, password)
print pcs.list_files('/').content.decode('unicode-escape').replace(',', '\n')
