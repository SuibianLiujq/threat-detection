import urllib2
import datetime
import json
import re
from store_json import *

def urlhaus():
	url = 'https://urlhaus.abuse.ch/downloads/csv/'
	f = urllib2.urlopen(url) 
	data = f.read().split('\r\n')[9:-1]
	# print data
	domain_dict = {}
	pattern = re.compile('^[a-zA-Z]+://([^/]*)')
	for term in data:
		new_term = term.split('","')
		# print new_term
		host = pattern.findall(new_term[2])[0]
		# print host
		domain_dict[host] = {
		'url': new_term[2],
		# 'status': new_term[3],
		'subtype': 'malware',
		# 'desc_maltype':'[malurl] ' +new_term[4]+'/'+new_term[5],
		'source': new_term[6].replace('"',""),
		}
	# print json.dumps(domain_dict,indent=4)
	return domain_dict

def main():
	domain_dict = urlhaus()
	store_json(domain_dict,'urlhaus')

# if __name__ == '__main__':
# 	urlhaus()