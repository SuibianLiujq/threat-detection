#! /usr/bin/python
# -*- coding:utf8 -*-
# author: songh

import sys
sys.path.append('..')
import os
import time
import datetime
import match_insert
import parser_config
import update_blacklist
import blacklist_tools
import ip_check_C2
from global_tools import set_logger,isOffline

second = datetime.timedelta(seconds=1)
day = datetime.timedelta(days=1)

# 检查函数入口, 检查网络情报和本地黑名单
# 返回匹配的ip
def checkES(startTime,indx,aggs_name,serverNum,dport,tday,offset,query_strs):
    # new check function
    mylog=set_logger()
    try:
        # print("Starting check command."), time.ctime()
        mylog.info("[mal_ip] Starting check command.Time is:{0}".format((startTime).strftime('%Y-%m-%d %H:%M:%S')))
        # execute the command
        gte = (startTime - delta-offset).strftime('%Y-%m-%d %H:%M:%S')
        lte = (startTime-offset).strftime('%Y-%m-%d %H:%M:%S')
        time_zone=''
        if(time.daylight==0):# 1:dst;
            time_zone="%+03d:%02d"%(-(time.timezone/3600),time.timezone%3600/3600.0*60)
        else:
            time_zone = "%+03d:%02d" % (-(time.altzone / 3600), time.altzone % 3600 / 3600.0 * 60)
        timestamp = (startTime).strftime('%Y-%m-%dT%H:%M:%S.%f') + time_zone
        # check
        all_ip=match_insert.main(tday,indx,gte,lte,aggs_name,timestamp,serverNum,dport,time_zone,query_strs)
        # print("check finish."), time.ctime()
        mylog.info("[mal_ip] Check finish.")
        # print"="*40
        return all_ip

    except Exception, e:
        # print e
        mylog.error(e)
        return {}

# 程序入口
def new_run(entertime,delta,serverNum,dport,offset,querys,indx='tcp-*',aggs_name='dip'):
    # new running procedure
    updatetime=datetime.datetime.now()
    startTime = entertime
    # beginTime = datetime.datetime.strptime(begin, '%Y-%m-%d %H:%M:%S')
    # flgnum is the running times per day
    flgnum=0
    # get format: "yy-mm-dd"
    tday=datetime.datetime.now().date()
    # runtime=0 # elapsed time of whole process,included check and merge
    mylog=set_logger()
    offlineFlg=isOffline() #
    while True:
        if(tday!=datetime.datetime.now().date()):
            flgnum=0 # reset flgnum per day
            tday=datetime.datetime.now().date()
            dirpath = parser_config.get_store_path() + str(tday) + os.path.sep
            os.mkdir(dirpath)
        while datetime.datetime.now() < startTime:
            #print('time sleep...')
            mylog.info("[mal_ip] Time sleeping ...")
            time.sleep((startTime-datetime.datetime.now()).total_seconds())
        try:
            # st=time.clock()
            #update source dataset
            if(offlineFlg is False):
                if(datetime.datetime.now()>=updatetime):
                    update_blacklist.main(tday,flgnum)
                    updatetime=updatetime+delta
            # check interval time is 5mins
            all_IP=checkES(startTime,indx,aggs_name,serverNum,dport,tday,offset,querys)
            #IP second check for C&C
            flg_C2=parser_config.get_ip_secondcheck()
            if(flg_C2==1):
                # 从info中IP检查，提升为warn
                mylog.debug('[mal_ip] Info_IP size:{}'.format(len(all_IP)))
                ip_check_C2.main(startTime,all_IP,serverNum,dport,indx)
            startTime = startTime + delta
            flgnum+=1
            # runtime=time.clock()-st# get the time of whole process
        except Exception, e:
            # print e
            mylog.error("[mal_ip] Ontime_run error:{0}".format(e))
            startTime = startTime + delta


if __name__=="__main__":
    #delta = 5mins
    delta,discard,offset=parser_config.getCheckDeltatime()
    # entertime =
    if(discard.lower()=='now'):
        tmpt= time.strftime("%Y-%m-%d %H:%M:%S")
        startTime = datetime.datetime.strptime(tmpt, '%Y-%m-%d %H:%M:%S')
    else:
        startTime = datetime.datetime.strptime(discard, '%Y-%m-%d %H:%M:%S')
    # entertime = time.strftime("%Y-%m-%d %H:%M:%S")
    serverNum,dport,indx,aggs_name,querys=parser_config.get_ES_info()
    #serverNum='172.23.2.96',dport = "9200";indx=tcp-*; aggs_name=dip
    #set global dic for storm suppression
    blacklist_tools.global_init()
    blacklist_tools.set_global_value('warn',[])
    new_run(startTime,delta,serverNum,dport,offset,querys,indx,aggs_name)
    # store_run()