#!/usr/bin/python
# -*- coding: utf-8 -*-

from store_json import store_json
import sys
import os
import json
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from conf import set_data_path


def localblacklist():
	dataPath = sys.path.join(set_data_path(), "local_bl_dns.json")
	with open(dataPath, 'r') as f:
		data = json.loads(f)
	for _, v in data:
		data["subtype"] = data.pop("type", "")
	return data

def main():
	ret_dict = localblacklist()
	store_json(ret_dict,'localblacklist')

