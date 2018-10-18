#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests,time
from store_json import store_json
from ip import blacklist_tools
from global_tools import set_logger

def firehol_level1(mylog):
    requests.adapters.DEFAULT_RETRIES = 5
    try:
        http = requests.get('http://iplists.firehol.org/files/firehol_level1.netset',verify=False,timeout=120)
        neir = http.text
        lines = neir.split('\n')
        del lines[-1]
    except Exception, e:
        mylog.warning("[mal_ip] Download firehol timeout!!!")
        lines=[]
    # print lines
    ip_dict = {}
    for line in lines:
        # print line
        ip_dict[line] = {
            'subtype':'suspect',
            'desc_subtype':'suspect ip;source:iplists.firehol.org/files/firehol_level1.netset',
            'level':'info',
            'fp':'unknown',
            'status':'unknown',
            'dport': -1,
            'mapping_ip': line,
            'date' : time.strftime('%Y-%m-%d',time.localtime(time.time()))
        }
    return ip_dict

def main():
    mylog=set_logger()
    dict = firehol_level1(mylog)
    #print len(dict.keys())
    store_json(dict, 'firehol_level1')
    #mylog.info("update firehol!")

if __name__=="__main__":
    main()