#!/usr/bin/python
# -*- coding: utf-8 -*-

import urllib2
import datetime
import json
from store_json import *

def CoinBlockerLists():
	url = 'https://zerodot1.gitlab.io/CoinBlockerLists/list.txt'
	try:
		f = urllib2.urlopen(url, timeout=120) 
	except Exception as e:
		return {}

	data = f.read().split('\n')[:-1]
	# print data
	domain_dict = {}
	for domain in data:
		domain_dict[domain] = {
		'subtype':'mining',
		'source':'https://zerodot1.gitlab.io/CoinBlockerLists/list.txt'
		}
	return domain_dict

def main():
	# print json.dumps(CoinBlockerLists(),indent=4)
	dict = CoinBlockerLists()
	store_json(dict,'CoinBlockerLists')

# if __name__ == '__main__':
# 	ret = CoinBlockerLists()
	# print json.dumps(ret)
	
