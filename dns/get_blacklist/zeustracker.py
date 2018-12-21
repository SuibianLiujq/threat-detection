#!/usr/bin/python
# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
import requests
import re
import os
# os.path.abspath(os.path.join(os.path.dirname(__file__),".."))
from store_json import *

def get_tr_list(url):
	'''
	获取html页面，提取所有的'tr'标签
	'''
	try:
		response = requests.get( url, verify=False, timeout=120)
		bs = BeautifulSoup( response.text, "html.parser")
		tr_list = bs.find_all('tr')
		return tr_list
	except Exception as e:
		return []
	

def zeustracker(url='https://zeustracker.abuse.ch/monitor.php?filter=all'):
	'''
	清洗zeustracker的数据
	'''
	tag = {
	u'1':'Bulletproof hosted',
	u'2':'Hacked webserver',
	u'3':'Free hosting service',
	u'4':'Unknown',
	u'5':'Hosted on a FastFlux botnet'
	}
	tr_list = get_tr_list(url)
	if not tr_list: 
		return {}

	domain_dict = {}
	for tr in tr_list[7:]:
		td_list = tr.find_all('td')
		host = td_list[2].get_text()
		domain_dict[host] = {
			'subtype': "c&c",
			# 'desc_maltype':'[zeus] '+td_list[1].get_text()+'/'+tag[td_list[4].get_text()],
			# 'status':td_list[5].get_text(),
			'source':'https://zeustracker.abuse.ch/monitor.php?filter=all'
		}

	return domain_dict


def main():
	dict = zeustracker()
	store_json(dict,'zeustracker')

# if __name__=="__main__":
#     dict = zeustracker()
#     store_json(dict,'zeustracker')