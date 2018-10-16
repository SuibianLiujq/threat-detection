#! /usr/bin/python
# -*- coding:utf8 -*-
# author: songh
import os
import time
import datetime
import match_insert
import parser_config
import update_blacklist
import blacklist_tools
import ip_check_C2
from global_tools import set_logger

second = datetime.timedelta(seconds=1)
day = datetime.timedelta(days=1)

# 检查函数入口, 检查网络情报和本地黑名单
# 返回匹配的ip
def checkES(startTime,indx,aggs_name,serverNum,dport,tday,offset,query_strs):
    # new check function
    mylog=set_logger()
    try:
        # print("Starting check command."), time.ctime()
        mylog.info("{0}[Starting mal_ip check command. Time is:{1}]{2}".format("="*15,(startTime).strftime('%Y-%m-%d %H:%M:%S'),"="*15))
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
        mylog.info("{0}mal_ip check finish.{1}".format("="*30,"="*30))
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
    updateFlg=parser_config.update_flg() #
    while True:
        if(tday!=datetime.datetime.now().date()):
            flgnum=0 # reset flgnum per day
            tday=datetime.datetime.now().date()
            dirpath = parser_config.get_store_path()[1] + str(tday) + os.path.sep
            os.mkdir(dirpath)
        while datetime.datetime.now() < startTime:
            #print('time sleep...')
            mylog.info("Time sleeping ...")
            time.sleep((startTime-datetime.datetime.now()).total_seconds())
        try:
            # st=time.clock()
            #update source dataset
            if(updateFlg==1):
                if(datetime.datetime.now()>updatetime):
                    update_blacklist.main(tday,flgnum)
                    updatetime=updatetime+delta
            # check interval time is 5mins
            all_IP=checkES(startTime,indx,aggs_name,serverNum,dport,tday,offset,querys)
            #IP second check for C&C
            flg_C2=parser_config.get_ip_secondcheck()
            if(flg_C2==1):
                # 从info中IP检查，提升为warn
                mylog.info('info_IP size:{}'.format(len(all_IP)))
                ip_check_C2.main(startTime,all_IP,serverNum,dport,indx)
            startTime = startTime + delta
            flgnum+=1
            # runtime=time.clock()-st# get the time of whole process
        except Exception, e:
            # print e
            mylog.error(e)


if __name__=="__main__":
    #delta = 5mins
    delta,discard,offset=parser_config.getCheckDeltatime()
    # entertime =
    if(discard.lower()=='now'):
        startTime= time.strftime("%Y-%m-%d %H:%M:%S")
    else:
        startTime = datetime.datetime.strptime(discard, '%Y-%m-%d %H:%M:%S')
    entertime = time.strftime("%Y-%m-%d %H:%M:%S")
    serverNum,dport,indx,aggs_name,querys=parser_config.get_ES_info()
    #serverNum='172.23.2.96',dport = "9200";indx=tcp-*; aggs_name=dip
    #set global dic for storm suppression
    blacklist_tools.global_init()
    blacklist_tools.set_global_value('warn',[])
    new_run(startTime,delta,serverNum,dport,offset,querys,indx,aggs_name)
    # store_run()