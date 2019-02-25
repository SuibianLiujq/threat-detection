#!/usr/bin/python
# -*- coding: utf-8 -*-

from store_json import store_json
import sys
import os
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from conf import set_data_path


def localblacklist():
	dataPath = os.path.join(set_data_path(), "local_bl_dns.json")
	with open(dataPath, 'r') as f:
		data = json.loads(f.read())
	for k in data:
		data[k]["subtype"] = data[k].pop("type", "")
	return data

def main():
	ret_dict = localblacklist()
	store_json(ret_dict,'localblacklist')

