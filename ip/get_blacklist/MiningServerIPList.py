#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests,datetime
from store_json import store_json
from lxml import etree
from ip import blacklist_tools
from global_tools import set_logger

def MiningServerIPList(mylog):
    requests.adapters.DEFAULT_RETRIES = 5
    try:
        http = requests.get('https://zerodot1.gitlab.io/CoinBlockerLists/MiningServerIPList.txt',verify=False,timeout=120)
        neir = http.text
        result=neir.split('\n')
        for line in result:
            if('#' in line and 'Last modified' in line):
                timelist=line.split(':')
                date=timelist[1].strip()+':'+timelist[2].strip()
                break
                # date=datetime.datetime.strftime(tmpdate,'%Y-%m-%d %H:%M')
        # html = etree.HTML(neir)
        # result = html.xpath('//td[starts-with(@id,"LC")]/text()')
        # time_source = result[4]
        # time_mediate =time_source.split(' ')
        # date = time_mediate[5]+'-'+time_mediate[4]+'-'+time_mediate[3]
        del result[:8]
    except Exception,e:
        mylog.warning("download MiningServerIP timeout!!!")
        result=[]
        date=''
    ip_dict = {}
    for ip in result:
        ip_dict[ip] ={
            'subtype':'mining',
            'desc_subtype':'mining pool ip;source:zerodot1.gitlab.io/CoinBlockerLists/MiningServerIPList.txt',
            'level':'info',
            'fp':'unknown',
            'status':'unknown',
            'dport': -1,
            'mapping_ip': ip,
            'date':date
        }
    return ip_dict

def main():
    mylog=set_logger()
    # mylog=[]
    dict = MiningServerIPList(mylog)
    #print len(dict.keys())
    store_json(dict, 'MiningServerIPList')
    #mylog.info("update mining pool!")

if __name__=="__main__":
    main()