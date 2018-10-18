# -*- coding: utf-8 -*-
import json
import datetime
import sys,os
sys.path.append('..')
from ip import parser_config
from ip import blacklist_tools
from global_tools import set_logger

def store_json(dict,name):
	'''
	保存为json
	'''
	mylog=set_logger()
	tday = datetime.datetime.now().date()
	file_name = name+ '.json'
	savepath=parser_config.get_store_path()+str(tday)+os.path.sep+file_name
	#mylog.info("path:{0}".format(savepath))
	try:
		with open(savepath,'w') as f:
			f.write(json.dumps(dict))
	except IOError:
		# print 'store_json Error'
		mylog.warning('[mal_ip] Change date time! download again!')

if __name__ == '__main__':
	dict={}
	name='1'
	store_json(dict,name)