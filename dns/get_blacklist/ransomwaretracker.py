#!/usr/bin/python
# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
import requests
import re
import os
from store_json import *

def get_tr_list(url):
	# 获取html页面，提取所有的'tr'标签
	try:
		response = requests.get(url, verify=False, timeout=120)
	except Exception as e:
		return []

	bs = BeautifulSoup(response.text,"html.parser")
	tr_list = bs.find_all('tr')
	return tr_list

def ransomwaretracker(url = 'https://ransomwaretracker.abuse.ch/tracker/online/'):
	# 清洗ransomwaretracker的数据
	tr_list = get_tr_list(url)
	if not tr_list:
		return {}

	domain_dict = {}
	pattern_ip = re.compile('^[0-9.]+$')
	# pattern_date = re.compile('^[0-9-]+')
	for tr in tr_list[1:]:
		td_list = tr.find_all('td')
		host = td_list[3].a.get_text()
		if not pattern_ip.findall(host):
			domain_dict[host] = {
			'subtype': 'ransomware',
			# 'desc_maltype':'[ransomware] '+td_list[1].span.get_text()+'/'+td_list[2].span.get_text(),
			# 'status':'online',
			'source':'https://ransomwaretracker.abuse.ch/tracker/online/'
			}
	return domain_dict


def main():
	dict = ransomwaretracker()
	store_json(dict,'ransomwaretracker')

# if __name__=="__main__":
#     dict = ransomwaretracker()
#     store_json(dict,'ransomwaretracker')