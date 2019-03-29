#! /usr/bin/python
# _*_ Coding:UTF-8 _*_
# author: songh

#update per 60mins
import requests,time
from store_json import store_json
from ip import blacklist_tools
from global_tools import set_logger

def bambenek_ip(mylog):
    requests.adapters.DEFAULT_RETRIES = 5
    try:
        http = requests.get('http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt', verify=False,timeout=120)
        neir = http.text
        lines = neir.split('\n')
        del lines[-1]
    except Exception, e:
        mylog.warning("[mal_ip] Download bambenek timeout!!!")
        lines=[]
    # print lines
    ip_dict = {}
    for line in lines:
        # print line
        if '#' in line or line == '':
            continue
        else:
            linelist=line.split(',')# line = ' ip,type,date,source'
            subtype=linelist[1].split('by')[-1].strip().replace(' ','_')
            subtype2=subtype.split('_')[-1].lower()
            if('/' in subtype):
                subtype=subtype.replace('/','or')
            ip_dict[linelist[0]] = {
                'subtype':"c&c",
                'desc_subtype':'{} ip;source:http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt'.format(subtype),
                'level':'info',
                'fp':'unknown',
                'status':'unknown',
                'dport':-1,
                'mapping_ip':linelist[0],
                'date' : time.strftime('%Y-%m-%d',time.localtime(time.time()))
            }
        # print ip_dict
    return ip_dict

def main():
    mylog = set_logger()
    dict = bambenek_ip(mylog)
    print len(dict)
    store_json(dict,'bambenek_ip')
    #mylog.info("update bambenek_ip!")
    # print 'update successfully'

if __name__=="__main__":
    main()