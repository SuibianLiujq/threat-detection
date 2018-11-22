#! /usr/bin/python
# _*_ Coding:UTF-8 _*_
# author: songh

import requests,time
from store_json import store_json
from ip import blacklist_tools
from global_tools import set_logger

# update per 15minsip
def ssl_abuse(mylog):
    requests.adapters.DEFAULT_RETRIES = 5
    try:
        http = requests.get('https://sslbl.abuse.ch/blacklist/sslipblacklist.csv', verify=False,timeout=120)
        neir = http.text
        lines = neir.split('\n')
        del lines[-1]
    except Exception, e:
        mylog.warning("[mal_ip] Download ssl_abuse timeout!!!")
        lines=[]
    # print lines
    ip_dict = {}
    for line in lines:
        # print line
        if '#' in line:
            continue
        else:
            lis=line.split(',')# line = 'DstIP,DstPort,Reason' -> lis =[DstIP,DstPort,Reason]
            if(len(lis)==3):
                tmpstr=lis[2].strip().replace(' ','_')
                ip_dict[lis[0]] = {
                    'subtype':tmpstr.split('_')[-1].lower(),
                    'desc_subtype':'{} ip;source:https://sslbl.abuse.ch/blacklist/sslipblacklist.csv'.format(lis[2]),
                    'level':'info',
                    'fp':'unknown',
                    'status':'unknown',
                    'dport':int(lis[1]),
                    'mapping_ip':lis[0],
                    'date' : time.strftime('%Y-%m-%d',time.localtime(time.time()))
                }
            # else:
            #     mylog.warn("[mal_ip] ssl_abuse data is no regular:{0}".format(lis))
        # print ip_dict
    return ip_dict

def main():
    mylog=set_logger()
    dict = ssl_abuse(mylog)
    #print len(dict)
    store_json(dict,'ssl_abuse')
    #mylog.info("update ssl_abuse!")
    # print 'update successfully'

if __name__=="__main__":
    main()