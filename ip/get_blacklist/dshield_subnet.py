#! /usr/bin/python
# _*_ Coding:UTF-8 _*_
# author: songh

import requests,time
from store_json import store_json
from ip import blacklist_tools
from global_tools import set_logger

# update per 15mins
# used to detect sip
def dshield_subnet(mylog):
    requests.adapters.DEFAULT_RETRIES = 5
    try:
        http = requests.get('http://feeds.dshield.org/block.txt',verify=False,timeout=120)
        neir = http.text
        lines = neir.split('\n')
        del lines[-1]
    except Exception, e:
        mylog.warning("download dshield_subnet timeout!!!")
        lines=[]
    # print lines
    ip_dict = {}
    for line in lines:
        # print line
        if '#' in line or line == '' or 'Start' in line:
            continue
        else:
            #line is 'Start	End	Netmask	Attacks	Name	Country	email'
            linelis=line.split('\t')
            subnet=linelis[0].strip()+'/24'
            ip_dict[subnet] = {
                'subtype':'dshield',
                'desc_subtype':'dshield attacking subnet;source:http://feeds.dshield.org/block.txt',
                'level':'info',
                'fp':'unknown',
                'status':'unknown',
                'dport':-1,
                'mapping_ip':subnet,
                'date' : time.strftime('%Y-%m-%d',time.localtime(time.time()))
            }
        # print ip_dict
    return ip_dict

def main():
    mylog=set_logger()
    dict = dshield_subnet(mylog)
    #print len(dict)
    store_json(dict,'dshield_subnet')
    #mylog.info("update dshield !")
    # print 'update successfully'

if __name__=="__main__":
    main()