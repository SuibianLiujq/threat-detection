#! /usr/bin/python
# _*_ Coding:UTF-8 _*_
# author: songh

import requests , re, json,time
from store_json import store_json
from ip import blacklist_tools
from global_tools import set_logger

# update per 12h, 144
def dropList(mylog):
    requests.adapters.DEFAULT_RETRIES = 5
    try:
        http = requests.get('https://www.spamhaus.org/drop/drop.txt',verify=False,timeout=120)
        neir = http.text
        lines = neir.split('\n')
        del lines[-1]
    except Exception, e:
        mylog.warning("[mal_ip] Download dropList timeout!!!")
        lines=[]
    # print lines
    ip_dict = {}
    for line in lines:
        # print line
        ips=line.split(';')[0].strip()
        if(not ips):
            continue
        else:
            ip_dict[ips] = {
                'subtype': 'suspect',
                'desc_subtype': 'suspect ip;source:https://www.spamhaus.org/drop/drop.txt',
                'level': 'info',
                'fp': 'unknown',
                'status': 'unknown',
                'dport': -1,
                'mapping_ip': ips,
                'date': time.strftime('%Y-%m-%d', time.localtime(time.time()))
            }
    return ip_dict

def main():
    mylog = set_logger()
    #mylog.info('download dropList...')
    dict = dropList(mylog)
    #mylog.info('dropList size:{}'.format(len(dict.keys())))
    store_json(dict, 'dropList')
    #mylog.info("update dropList!")

if __name__=="__main__":
    main()