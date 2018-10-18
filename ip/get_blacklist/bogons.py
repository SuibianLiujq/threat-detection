#! /usr/bin/python
# _*_ Coding:UTF-8 _*_
# author: songh

import requests,time
from store_json import store_json
from ip import blacklist_tools
from global_tools import set_logger

# update per 240minsip
def bogons_ip(mylog):
    requests.adapters.DEFAULT_RETRIES = 5
    try:
        http = requests.get('http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt',verify=False,timeout=120)
        neir = http.text
        lines = neir.split('\n')
        del lines[-1]
    except Exception, e:
        mylog.warning("[mal_ip] Download bogons timeout!!!")
        lines=[]
    # print lines
    ip_dict = {}
    for line in lines:
        # print line
        if '#' in line or line == '':
            continue
        else:
            ip_dict[line] = {
                'subtype':'bogons',
                'desc_subtype':'bogons subnet;source:http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt',
                'level':'info',
                'fp':'unknown',
                'status':'unknown',
                'dport':-1,
                'mapping_ip':line,
                'date' : time.strftime('%Y-%m-%d',time.localtime(time.time()))
            }
        # print ip_dict
    return ip_dict

def main():
    mylog = set_logger()
    dict = bogons_ip(mylog)
    print len(dict)
    store_json(dict,'bogons')
    #mylog.info("update bogons_ip!")
    # print 'update successfully'

if __name__=="__main__":
    main()