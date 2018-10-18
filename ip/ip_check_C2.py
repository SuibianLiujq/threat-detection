#! /usr/bin/python
# -*- coding: utf-8 -*-
# author: songh

import sys
sys.path.append('..')
from elasticsearch import Elasticsearch
import time
import datetime
import blacklist_tools,parser_config
from global_tools import set_logger

# !/usr/bin/python
# -*- coding: utf-8 -*-

import json

def get_date_flow(es, gte, lte, time_zone, dip,index):
    search_option = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": "dip:{}".format(dip),
                            'analyze_wildcard': True
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gte": gte,
                                "lte": lte,
                                "format": "yyyy-MM-dd HH:mm:ss",
                                "time_zone": time_zone
                            }
                        }
                    }
                ],
                "must_not": []
            }
        },
        "_source": {
            "excludes": []
        },
        "aggs": {
            "sip": {
                "terms": {
                    "field": "sip",
                    "size": 1000,
                    "order": {
                        "flow": "desc"
                    }
                },
                "aggs": {
                    "flow": {
                        "sum": {
                            "field": "flow"
                        }
                    },
                    "date": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "interval": "1m",
                            "time_zone": time_zone,
                            "min_doc_count": 1
                        },
                        "aggs": {
                            "flow": {
                                "sum": {
                                    "field": "flow"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    result = es.search(
        index=index,
        body=search_option
    )
    return result




def calc_median(datalist):
    datalist.sort()
    half = len(datalist) // 2
    return (datalist[half] + datalist[~half]) / 2.0


def calc_MAD(datalist):
    median = calc_median(datalist)
    return calc_median([abs(data - median) for data in datalist])

# Second_check: 1）根据dip查找某段时间内所有与其通信的sip在每分钟flow计数；
#             2）根据flow计数的序列判断是否有异常
# return: 返回有问题的sip list
def Second_check(es, gte, lte, time_zone, dip,index,mylog,siplist):
    #mylog.info('get flow from ES.')
    res = get_date_flow(es=es, gte=gte, lte=lte, time_zone=time_zone, dip=dip,index=index)
    ret_siplist = []
    # each sip_item has only one sip but many flows in different time
    for sip_item in res["aggregations"]["sip"]["buckets"]:
        if(sip_item["key"] in siplist):# sip appear in last 5 mins then check 24h
            datelist = []
            flowlist = []
            for item in sip_item["date"]["buckets"]:
                datelist.append(item["key"])
                flowlist.append(item["flow"]["value"])
            if len(datelist) < 3:
                continue
            #mylog.info('*_*_* len of datelist:{} *_*_*'.format(len(datelist)))
            date_dev = [datelist[i + 1] - datelist[i] for i in range(len(datelist) - 1)]
            #		print date_dev
            #		print flowlist
            #mylog.info('*_*_* result of date_dev:{} *_*_*'.format(calc_MAD(date_dev)))
            #mylog.info('*_*_* result of flowlist:{} *_*_*'.format(calc_MAD(flowlist)))

            # print calc_MAD(flowlist)
            if (calc_MAD(date_dev) <= 60000) and (calc_MAD(flowlist) <= 1):
                ret_siplist.append(sip_item["key"])
                #mylog.info('*_*_* appending sip:{}. *_*_*'.format(sip_item["key"]))
    return ret_siplist# sip

class ESclient(object):
    def __init__(self,server='192.168.0.122',port='9222'):
        self.__es_client=Elasticsearch([{'host':server,'port':port}])
    # get alert's dip list
    def get_es_ip(self,index,gte,lte,aggs_name,time_zone,querystr,rangetime,size=500000):
        search_option={
            "size": 0,
            "query": {
              "bool": {
                "must": [
                    {
                        "query_string": querystr
                    },
                    {
                        "range": rangetime
                    }
                ],
                "must_not": []
              }
            },
            "_source": {
                "excludes": []
            },
            "aggs": {
                "get": {
                    "terms": {
                        "field": aggs_name,
                        "size": size,
                        "order": {
                            "_count": "desc"
                        }
                    }
                }
            }
        }
        search_result=self.__es_client.search(
            index=index,
            body=search_option
            )
        clean_search_result = search_result['aggregations']["get"]['buckets']
        ip = []
        for temp in clean_search_result:
            ip.append(temp['key'])
        return ip

    def es_index(self, doc):
        # 数据回插es的alert-*索引
        ret = self.__es_client.index(
            index='alert-{}'.format(datetime.datetime.now().strftime('%Y-%m-%d')),
            doc_type='netflow_v9',
            body=doc
        )
    # get all alerts' infomation and return dict={dip:{value},dip2:{},...}
    def es_search_alert(self,index,gte,lte,filetype,time_zone,querystr,rangetime,aggs):
        search_option = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "query_string": querystr
                        },
                        {
                            "range": rangetime
                        }
                    ],
                    "must_not": []
                }
            },
            "_source": {
                "excludes": []
            },
            "aggs": {
                "get": aggs
                }
        }
        search_result = self.__es_client.search(
            index=index,
            body=search_option
        )
        allrecord={}
        clean_search_result = search_result['hits']["hits"]
        for temp in clean_search_result:
            #temp is dict
            dip=temp["_source"]["dip"]
            allrecord[dip]=temp["_source"]
        return allrecord

    def check_5mins(self,gte1,lte,time_zone,dip,index,mylog):
        #self,gte1,lte,time_zone,dip,mylog
        #mylog.info('start check sip in last 5mins,dip:{0}'.format(dip))
        search_option = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "query_string": {
                                "query": "dip:{}".format(dip),
                                'analyze_wildcard': True
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte1,
                                    "lte": lte,
                                    "format": "yyyy-MM-dd HH:mm:ss",
                                    "time_zone": time_zone
                                }
                            }
                        }
                    ],
                    "must_not": []
                }
            },
            "_source": {
                "excludes": []
            },
            "aggs": {
                "sip": {
                    "terms": {
                        "field": "sip",
                        "size": 1000,
                        "order": {
                            "_count": "desc"
                        }
                    }
                }
            }
        }
        search_result = self.__es_client.search(
            index=index,
            body=search_option
        )
        allrecord=[]
        # mylog.info('get last 5mins sip.')
        clean_search_result = search_result['aggregations']["sip"]['buckets']
        for temp in clean_search_result:
            #temp is dict
            allrecord.append(temp['key'])
        # return sip
        return allrecord

    def secondcheck(self,gte1,gte2,lte,time_zone,dip,index,mylog):
        # mylog.info('*=*=*=[start second check.]*=*=*=')
        # check sip，dip in last 5 mins
        siplis=self.check_5mins(gte1,lte,time_zone,dip,index,mylog)
        # check sip，dip in last 24h
        return Second_check(self.__es_client, gte2, lte, time_zone, dip,index,mylog,siplis)


'''
searchAndInsert:1)modified the record (level:warning,add sip)
                2)insert to es
alerts: the alerts infomation
ipdict: dip after second check,and it's reference sip
'''
def searchAndInsert(alerts,ipdict,es,mylog):
    alert_dip=alerts.keys()
    warning_dip=ipdict.keys()
    #mylog.info('start second check insert.')
    for tmp in warning_dip:
        if(tmp in alert_dip):# make sure that dip in alerts
            for tsip in ipdict[tmp]:# insert sip/dip to es
                doc=alerts[tmp]
                doc['level']="warn"
                doc['sip']=tsip
                es.es_index(doc)
                #mylog.info('insert WARNING!!!')
    #mylog.info('second check insert finished.')

def list_filter(wlis,allwarn):
    # for Storm suppression
    # wlis is Queue,[{},{},{},...]
    # allwarn is new check records
    # return subwarn which (sip,dip) not in wlis
    # first step: get (sip,dip) list
    warnlis=[]
    for it in wlis:
        for ii in it.keys():# ii is dip
            for ss in it[ii]: #ss is sip
                warnlis.append((ss,ii))
    alllis=[]
    for dd in allwarn.keys():#dd is dip
        for sss in allwarn[dd]:# sss is sip
            alllis.append((sss,dd))
    # second step: get new(sip,dip) list
    alllis=list(set(alllis)-set(warnlis))
    # finally, change type as dic ( {'dip:[sips],...})
    subwarn={}
    for jj in alllis:# jj is (sip,dip)
        if(jj[1] in subwarn.keys()):
            subwarn[jj[1]].append(jj[0])
        else:
            subwarn[jj[1]]=[]
            subwarn[jj[1]].append(jj[0])
    return subwarn

def main(startTime,all_IP,serverNum,dport,index="tcp-*"):
    # all_IP is a dips inserted as an information alert into es
    mylog=set_logger()
    # startTime=datetime.datetime.now()
    delta1=datetime.timedelta(minutes=5)
    gte1 = (startTime - delta1).strftime('%Y-%m-%d %H:%M:%S')
    lte = (startTime).strftime('%Y-%m-%d %H:%M:%S')
    time_zone = ''
    if (time.daylight == 0):  # 1:dst;
        time_zone = "%+03d:%02d" % (-(time.timezone / 3600), time.timezone % 3600 / 3600.0 * 60)
    else:
        time_zone = "%+03d:%02d" % (-(time.altzone / 3600), time.altzone % 3600 / 3600.0 * 60)
    timestamp = (startTime).strftime('%Y-%m-%dT%H:%M:%S.%f') + time_zone
    # serverNum='localhost'
    # dport='9200'
    #first step,get the all_IP
    # mylog.info('start check alert info.')
    # diplist,es,allalerts=checkAlert('alert-*',gte1,lte,time_zone,serverNum,dport)
    es = ESclient(server=serverNum, port=dport)
    #second step
    delta2=datetime.timedelta(days=1)
    gte2 = (startTime - delta2).strftime('%Y-%m-%d %H:%M:%S')
    lte = (startTime).strftime('%Y-%m-%d %H:%M:%S')
    allwarn={}# {dip:[sip,sip,sip...],ip:[],...},

    try:
        mylog.info('[mal_ip] Start second check.')
        for dip in all_IP.keys():
            allwarn[dip]=es.secondcheck(gte1,gte2,lte,time_zone,dip,index,mylog)
        mylog.info('[mal_ip] Second check finish.')
    except Exception,e:
        mylog.error('[mal_ip] Second_check error:{}'.format(e))
    # Storm suppression
    #mylog.info("[start Storm suppression!]")
    warnLis=blacklist_tools.get_global_value('warn')# insert records
    if(warnLis==None):
        mylog.error('[mal_ip] Storm error: global name error!')
        subWarn={}
    else:
        # get warnLis size
        lisSize=parser_config.get_WarnLis_size()
        if(len(warnLis)==0):
            warnLis.append(allwarn)
            subWarn=allwarn
        elif(len(warnLis)<lisSize):
            subWarn=list_filter(warnLis,allwarn)
            warnLis.append(subWarn)
        elif(len(warnLis)==lisSize):
            subWarn = list_filter(warnLis, allwarn)
            warnLis.pop(0)
            warnLis.append(subWarn)

    #insert warning alert
    try:
        searchAndInsert(all_IP,subWarn,es,mylog)
    except Exception,e:
        mylog.error('[mal_ip] SearchAndInsert error:{}'.format(e))
