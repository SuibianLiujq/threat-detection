#!/usr/bin/python
# -*- coding: utf-8 -*-

from store_json import store_json
import sys
import os
sys.path.append(os.path.join(os.path.split(__file__)[0],"../"))
from conf import set_data_path, get_intel_source


def localblacklist():
	intelSourceList = get_intel_source()
	ret_dict = {}
	for item in intelSourceList:
		for domain in item["host"]:
			ret_dict[domain] = {
				'source'  : item["source"],
				'subtype' : item["type"]
			}
	return ret_dict

def main():
	ret_dict = localblacklist()
	store_json(ret_dict,'localblacklist')

