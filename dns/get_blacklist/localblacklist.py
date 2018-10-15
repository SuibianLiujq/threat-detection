#!/usr/bin/python
# -*- coding: utf-8 -*-

from store_json import store_json
import sys
import os
sys.path.append('../')
from configuration import set_data_path


def localblacklist():
	data_path = set_data_path()
	blacklist_dir = os.path.join(data_path,'local_Blacklist.txt')
	with open(blacklist_dir,'r') as f:
		text = f.read()
	text = text.split('\n')[6:-1]
	ret_dict = {}
	for row in text:
		row = row.split(' ')
		ret_dict[row[0]] = {
			'source' : row[1],
			'subtype' : row[2]
		}
	return ret_dict

def main():
	ret_dict = localblacklist()
	store_json(ret_dict,'localblacklist')

