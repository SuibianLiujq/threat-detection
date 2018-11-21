#!/usr/bin/python
# -*- coding:utf8 -*-
# @Time    : 2018/11/21 11:29
# @Author  : songh
# @File    : check_dns.py
# @Software: PyCharm

import sys,os
sys.path.append(os.path.abspath(os.path.pardir))
import ES_class
import my_tools
from global_tools import set_logger

'''
step1: 获取过去24h数据，过滤得到domain，answer
step2: 处理domain
step3: 处理answer
step4: 拼成info告警内容，发出告警
'''
def first_check(starttime,delta,timezone):
    mylog=set_logger()
    #dttime=datetime.timedelta(days=1)
    server,port,alert_idx,data_idx=my_tools.get_es_server()
    gte=(starttime-delta).strftime('%Y-%m-%d %H:%M:%S')
    lte=starttime.strftime('%Y-%m-%d %H:%M:%S')
    es=ES_class.ESClient(iserver=server,iport=port)
    #get dns data
    dataset=es.get_dns_data(data_idx,gte,lte,timezone)
    # clean
    newdata=my_tools.clean_dns_data(dataset)
    mylog.debug("[surbl] dns data size:{0}".format(len(newdata)))
    # analysis
    mylog.debug("[surbl] analyse data ...")
    docs=my_tools.analyse_info(newdata)
    # insert es
    mylog.debug("[surbl] insert ES ...")
    my_tools.insert_alert(es,docs,alert_idx)


# 检查开始
def check_start(starttime,deltatime,timezone):
    first_check(starttime,deltatime,timezone)