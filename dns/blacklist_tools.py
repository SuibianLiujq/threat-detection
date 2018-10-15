#!/usr/bin/python
# -*- coding: utf-8 -*-

import datetime
import json
import os

# def judge_level(fp,status):
# 	# 根据fp、status判断level
# 	if status:
# 		if fp:
# 			if status == 'online':
# 				if fp == 'low':
# 					return 'WARNING'
# 	return 'INFO'


# def judge_unknown(str1,str2):
# 	# 两个情报源发现相同的domain时，整合情报，判断fp与status的值
# 	if str1 == str2:
# 		return str1
# 	elif str1 != 'unknown' and str2 !='unknown':
# 		return 'unknown'
# 	elif str1 != 'unknown':
# 		return str1
# 	elif str2 != 'unknown':
# 		return str2

# def judge_date(str1,str2):
# 	# 两个情报源发现相同的domain时，记录最近的时间整合情报
# 	if str1 == str2:
# 		return str1
# 	else:
# 		date1 = datetime.datetime.strptime(str1,'%Y-%m-%d')
# 		date2 = datetime.datetime.strptime(str2,'%Y-%m-%d')
# 		if date1>date2:
# 			return date1.strftime('%Y-%m-%d')
# 		else:
# 			return date2.strftime('%Y-%m-%d')

def update_dict(dict1,dict2):
	# 合并两个字典
	domain_insection = set(dict1.keys()) & set(dict2.keys())
	# print domain_insection
	ret_dict = dict(dict1,**dict2)
	if domain_insection: 
		#如果两个源存在相同domain情报
		for domain in domain_insection:
			temp_dict = {}
			for key in dict1[domain].keys():
				#合并前先两个情报源关于domain的情报是否有重合
				if dict2[domain].get(key):
					#如果情报有重合，看是否相同，不同则用';'分割记录
					if dict1[domain][key] != dict2[domain][key]:
						temp_dict[key] = dict1[domain][key]+';'+dict2[domain][key]
				else:
					temp_dict[key] = dict1[domain][key]
			ret_dict[domain] = dict(dict2[domain],**temp_dict)

	return ret_dict 

def saveAsJSON(date,dict1,path,name):
	# 保存为json
	file_name = os.path.join(path , name + '-' + str(date) + '.json')
	try:
		with open(file_name,'w') as f:
			f.write(json.dumps(dict1))
	except IOError as e:
		raise e



def load_dict(filedir):
	# 加载本地的json文件
	try:
		with open(filedir,'r') as f:
			dict1=json.loads(f.read())
			# print dict1
			return dict1
	except IOError as e:
		raise e

def insert(Trie,element):
	# 将element插入Trie
	if element:
		item=element.pop()
		if item not in Trie:
			Trie[item]={}
		Trie[item]=insert(Trie[item],element)
	return Trie

def create_Trie(blacklist):
	# 根据blacklist创建Trie
	domainTrie={}
	# print blacklist
	for domain in blacklist:
		domainTrie=insert(domainTrie,domain)
	return domainTrie

# load_dict('.\data\\source-2018-03-11.json')