# -*- coding: utf-8 -*-
import json

def store_json(dict,name):
	# 保存为json
	file_name = name+ '.json'
	try:
		with open(file_name,'w') as f:
			f.write(json.dumps(dict))
	except IOError:
		print 'Error'