#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
sys.path.append('..')
from elasticsearch import Elasticsearch
import datetime,sys
from blacklist_tools import load_dict,load_whitelist
import blacklist_tools,parser_config
import os
import check_XForce as xf
from global_tools import set_logger

class ESclient(object):
	def __init__(self,server='192.168.0.122',port='9222'):
		self.__es_client=Elasticsearch([{'host':server,'port':port}])

	def get_es_ip(self,index,gte,lte,aggs_name,time_zone,query_str="",size=500000):
		search_option={
            "size": 0,
            "query": {
              "bool": {
                "must": [
                    {
                        "query_string": {
                            #"query": "NOT dip:[192.168.0.0 TO 192.168.255.255] AND NOT dip:[172.16.0.0 TO 172.31.255.255] AND NOT dip:[10.0.0.0 TO 10.255.255.255] AND NOT dport:445 AND unknown_conn:0",
                            "query":query_str,
                            "analyze_wildcard": True
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gte": gte,
                                "lte": lte,
                                "format": "yyyy-MM-dd HH:mm:ss",
                                "time_zone":time_zone
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
                "getDip": {
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
		clean_search_result = search_result['aggregations']["getDip"]['buckets']
		ip = []#dips
		for temp in clean_search_result:
			ip.append(temp['key'])
		return ip

	def es_index(self,doc):
		'''
		数据回插es的alert-*索引
		'''
		ret = self.__es_client.index(
			index = 'alert-{}'.format(datetime.datetime.now().strftime('%Y-%m-%d')),
			doc_type = 'netflow_v9',
			body = doc
			)

# 获取目录下所有文件
def get_all_file(path):
    if(os.path.exists(path)):
        filelist=os.listdir(path)
        return filelist

'''
dataset是blacklist data（net or local）,es_ip是es中获取的ip
step1: get dataset from file and separate them into three parts
step2: full match
step3: range match
step4: separate the subnet dataset into two parts(lpm,full)
step5: lpm match and subnet full match
step6: whitelist filter
'''
def treatip(dataset,es_ip):
    mylog=set_logger()
    full,segment,subnet=blacklist_tools.separate_ip(dataset)#dataset is dict
    # match procedure
    # full match
    full_list = full.keys()
    # return fullmatchlist,type is list
    fullmatchlist=blacklist_tools.ip_full_match(full_list, es_ip)
    # segment match, segmentlist:[{ip:ipsegment},{},...]
    segmentlist=blacklist_tools.int_ip_range(segment,es_ip)
    subnet_lpm = {}
    subnet_full = {}
    sndict = {}
    sn_lte16 = {}
    # read conf file to choose the methods
    flg_lpm,flg_full=parser_config.get_method()
    if(1==flg_lpm):
        # subnet match by lpm,subnet_lpm is match results;sndict and sn_lte16 is original subnet data
        #mylog.info('start lpm match')
        #atime=time.time()
        subnet_lpm,sndict,sn_lte16,sn_gte24=blacklist_tools.subnet_lpm(subnet,es_ip)
        #ftime=time.time()-atime
        #mylog.info('times:{}'.format(ftime))
        #mylog.info('finish lpm match')
    if(1==flg_full):
        #subnet match by zhou, parameters are snlist and es_ip
        # mylog.info('sndict size: %d'%len(sndict))
        # mylog.info('sn_lte16 size: %d' % len(sn_lte16))
        #mylog.info('start range subnet match')
        subnet_full=blacklist_tools.subnet_range_match(sn_gte24,es_ip)
        #mylog.info('finish range subnet match')
    #whitelist
    wlflg, whitepath = parser_config.get_self_filelist('whitelist')
    if(wlflg==1):
        #get whilelist
        if (os.path.exists(whitepath)):
            filelist = get_all_file(whitepath)
            for fname in filelist:
                fpath = whitepath + fname
                #白名单读取方式不一样, whitedata is dict
                whitedata = blacklist_tools.load_whitelist(fpath)
                #filter procedure
                fullmatchlist, segmentlist, subnet_lpm, subnet_full=blacklist_tools.whitelist_filter(fullmatchlist,segmentlist,subnet_lpm,subnet_full,whitedata)
        else:
            mylog.info('no self_whitelist_path')

    # return match results
    return fullmatchlist,segmentlist,subnet_lpm,subnet_full

# check x-force
def get_xforce(odata,datatype = 0):
    # datatype=1 means odata is fullmatch data
    #mylog = blacklist_tools.getlog()
    #mylog.info('start get_xforce!')
    if(datatype==1):
        # fullmatch data =[ip,ip,ip...]
        retdata=xf.start(1,odata)
    else:
        # other data = [{ip:matchtype},{},{},...]
        ipset=[]
        for ii in odata:
            ipset.append(ii.keys()[0])
        retdata=xf.start(1,ipset)
    # retdata is dict of xforce info
    #mylog.info('finish get_xforce')
    return retdata

# 将full match格式插入es
def full_match_type(es_insert,data,msg,index,timestamp,aggs_name):
    mylog=set_logger()
    tmpThreat={}
    # check by x-force
    new_fullmatch = get_xforce(data, 1)
    # new_fullmatch_list=new_fullmatch.keys()
    for i in range(len(data)):
        try:
            doc = {}
            doc['level'] = msg[data[i]]['level']
            doc['type'] = 'mal_ip'
            doc['desc_type'] = '[mal_ip] Request of suspect IP detection.'
            doc['desc_subtype'] = msg[data[i]]['desc_subtype']
            doc['subtype'] = msg[data[i]]['subtype']
            doc['match_type'] = "full_match"
            doc[aggs_name] = data[i]
            doc['@timestamp'] = timestamp
            doc['index'] = index
            # mylog.info('msg start{0}'.format(new_fullmatch[fullmatch[i]]))
            # =========排查空值！==============
            if (new_fullmatch[data[i]].has_key('score') and (new_fullmatch[data[i]]["score"])):
                doc['xforce_marks'] = float(new_fullmatch[data[i]]["score"])
            elif ((not new_fullmatch[data[i]].has_key('score')) or (not (new_fullmatch[data[i]]["score"]))):
                doc['xforce_marks'] = 0
            else:
                doc['xforce_marks'] = float(new_fullmatch[data[i]]["score"])
            # msg info
            msg_info = ''
            if(new_fullmatch[data[i]].has_key("cats")):
                cats = new_fullmatch[data[i]]["cats"]
                for ky, vals in cats.items():
                    msg_info = msg_info + str(ky) + ':' + str(vals) + '%;'
            if (new_fullmatch[data[i]].has_key("geo") and (new_fullmatch[data[i]]["geo"]).strip()):
                msg_info = msg_info + 'geo:' + new_fullmatch[data[i]]["geo"] + ';'
            if (new_fullmatch[data[i]].has_key("company") and (new_fullmatch[data[i]]["company"]).strip()):
                msg_info = msg_info + 'company:' + new_fullmatch[data[i]]["company"]
            if(msg_info[-1]==';'):
                doc['xforce_msg'] = msg_info[:-1]
            else:
                doc['xforce_msg'] = msg_info
            es_insert.es_index(doc)
            tmpThreat[data[i]] = doc
            #mylog.info('insert fullmatch with xforce')
        except Exception, e:
            mylog.error(e)
            doc = {}
            doc['level'] = msg[data[i]]['level']
            doc['type'] = 'mal_ip'
            doc['desc_type'] = '[mal_ip] Request of suspect IP detection.'
            doc['desc_subtype'] = msg[data[i]]['desc_subtype']
            doc['subtype'] = msg[data[i]]['subtype']
            doc['match_type'] = "full_match"
            doc[aggs_name] = data[i]
            doc['@timestamp'] = timestamp
            doc['index'] = index
            es_insert.es_index(doc)
            tmpThreat[data[i]] = doc
            # print 'full_match_insert'
            mylog.info('insert fullmatch by defaut')
    return tmpThreat

# 将lpm,range格式统一插入es
# data format: [{ip:matched_ip},{},{},...]
def other_match_type(es_insert,data,match_types,msg,index,timestamp,aggs_name):
    mylog=set_logger()
    tmpThreat={}
    # check by x-force
    new_subnetlpm = get_xforce(data, 0)
    # new_fullmatch_list=new_fullmatch.keys()
    for i in range(len(data)):
        try:
            doc = {}
            # segment insert,
            # ip_es 原es IP
            ip_es=data[i].keys()[0]# get alert ip
            # ip_es,对应的匹配的ip
            ipseg=data[i][ip_es]# alert match type
            # print ipseg
            if(match_types == "subnet_lpm_match"):
                #lpm找不到对应ip,随机取一个当前黑名单的ip，获取对应属性字段
                key1=msg.keys()[0]
                ipseg=key1
                tmptype=msg[key1]['desc_subtype'].split(';')
                doc['desc_subtype'] = tmptype[0].split(':')[0]+';'+tmptype[1]
            else:
                doc['desc_subtype'] = msg[ipseg]['desc_subtype']
            doc['level'] = msg[ipseg]['level']
            doc['type'] = 'mal_ip'
            doc['desc_type'] = '[mal_ip] Request of suspect IP detection.'
            doc['subtype'] = msg[ipseg]['subtype']
            doc['match_type'] = match_types
            doc[aggs_name] = ip_es
            doc['@timestamp'] = timestamp
            doc['index'] = index
            if (new_subnetlpm[ip_es].has_key("score") and (new_subnetlpm[ip_es]["score"])):
                doc['xforce_marks'] = float(new_subnetlpm[ip_es]["score"])
            elif((not new_subnetlpm[ip_es].has_key("score")) or (not (new_subnetlpm[ip_es]["score"]))):
                doc['xforce_marks'] = 0
            else:
                doc['xforce_marks'] = float(new_subnetlpm[ip_es]["score"])
            # msg info
            msg_info = ''
            if(new_subnetlpm[ip_es].has_key("cats")):
                cats = new_subnetlpm[ip_es]["cats"]
                for ky, vals in cats.items():
                    msg_info = msg_info + str(ky) + ':' + str(vals) + '%;'
            if(new_subnetlpm[ip_es].has_key("geo") and (new_subnetlpm[ip_es]["geo"]).strip()):
                msg_info = msg_info + 'geo:' + new_subnetlpm[ip_es]["geo"] + ';'
            if(new_subnetlpm[ip_es].has_key("company") and (new_subnetlpm[ip_es]["company"]).strip()):
                msg_info = msg_info + 'company:' + new_subnetlpm[ip_es]["company"]
            if(msg_info[-1]==';'):
                doc['xforce_msg'] = msg_info[:-1]
            else:
                doc['xforce_msg'] = msg_info
            es_insert.es_index(doc)
            tmpThreat[ip_es] = doc
            #mylog.info('insert {0} with xforce'.format(match_types))
        except Exception, e:
            mylog.error(e)
            doc = {}
            # segment insert
            ip_es=data[i].keys()[0]# get alert ip
            # print ip_es
            ipseg=data[i][ip_es]# alert match type
            # print ipseg
            if(match_types == "subnet_lpm_match"):
                key1=msg.keys()[0]
                ipseg=key1
                tmptype=msg[key1]['desc_subtype'].split(';')
                doc['desc_subtype'] = tmptype[0].split(':')[0]+';'+tmptype[1]
            else:
                doc['desc_subtype'] = msg[ipseg]['desc_subtype']
            doc['level'] = msg[ipseg]['level']
            doc['type'] = 'mal_ip'
            doc['desc_type'] = '[mal_ip] Request of suspect IP detection.'
            doc['subtype'] = msg[ipseg]['subtype']
            doc['match_type'] = match_types
            doc[aggs_name] = ip_es
            doc['@timestamp'] = timestamp
            doc['index'] = index
            tmpThreat[ip_es] = doc
            # print 'subnet_lpm_insert'
            mylog.info('insert {0} by default'.format(match_types))
    return tmpThreat

#get four dateset from four match methods , insert separately
# msg is original dataset
# 根据不同数据格式，分两种插入方式
def insert_result(index,aggs_name,timestamp,serverNum,dport,fullmatch,segmentmatch,subnetlpm,subnetfull,msg):
    es_insert = ESclient(server=serverNum, port=dport)
    #mylog=set_logger()
    threat_ip={}# finally dict of matched ip,最终匹配成功的ip
    #white list filter ips
    if len(fullmatch) > 0:# fullmatch=[ip,ip,ip...]
        tmp=full_match_type(es_insert,fullmatch,msg,index,timestamp,aggs_name)
        threat_ip=dict(threat_ip,**tmp)

    if len(segmentmatch) > 0:#segmentmatch=[{ip:range},{},{}...]
        tmp=other_match_type(es_insert,segmentmatch,"segment_match",msg,index,timestamp,aggs_name)
        threat_ip=dict(threat_ip,**tmp)#merge

    if len(subnetlpm) > 0:#subnetlpm=[{ip:"lpm_match"},{},{}...]
        tmp=other_match_type(es_insert,subnetlpm,'subnet_lpm_match',msg,index,timestamp,aggs_name)
        threat_ip=dict(threat_ip,**tmp)

    if len(subnetfull) > 0:# subnet_range data, subnetfull=[{ip:ipsubnet},{},{}]
        tmp=other_match_type(es_insert,subnetfull,'subnet_fullmatch',msg,index,timestamp,aggs_name)
        threat_ip=dict(threat_ip,**tmp)

    return threat_ip

#具体处理网络情报过程
def checkAndInsert(path,filelist,ip_es_list,index,aggs_name,timestamp,serverNum,dport):
    # check each file
    mylog=set_logger()
    all_threatIP={}
    for fname in filelist:
        mylog.info('-*-*-*-*-file:{}-*-*-*-*-'.format(fname))
        fpath = path + fname
        dataset = load_dict(fpath)
        #mylog.info("dataset len:{0}".format(len(dataset)))
        if (dataset):
            msg = dataset[dataset.keys()[0]]
            # get match result
            fullmatch, segmentmatch, subnetlpm, subnetfull = treatip(dataset,ip_es_list)
            threatIP=insert_result(index,aggs_name,timestamp,serverNum,dport,fullmatch,segmentmatch,subnetlpm,subnetfull,dataset)
            # merge
            if(threatIP):
                all_threatIP=dict(all_threatIP,**threatIP)
    return all_threatIP

'''
step1: get the saved file
step2: divide the data into 3 parts(ip_32/ip_seg/ip_subnet),and match each parts
step3: insert the threat info into es
'''
def main(tday,index, gte, lte, aggs_name, timestamp,serverNum,dport,time_zone,querys_str):
    mylog = set_logger()
    path=parser_config.get_store_path()[1]+str(tday)+os.path.sep
    cnt=0
    allThreatIP={}# 有问题的dip
    # 不联网情况下，尝试使用过去7天的数据检查
    while(cnt<8):
        if(os.path.exists(path)):
            filelist=get_all_file(path)
            break
        elif cnt==7:
            #default file path
            dflg, defaultpath = parser_config.get_self_filelist('defaultlist')
            if(dflg==1):
                filelist = get_all_file(defaultpath)
            else:
                filelist=[]
            break
        else:
            # check last 7 days file
            lday=tday+datetime.timedelta(-1)
            path = parser_config.get_store_path()[1] + str(lday) + os.path.sep
            cnt=cnt+1
    #get es list
    es = ESclient(server =serverNum,port=dport)
    # mylog.info('connected with es')
    ip_es_list = es.get_es_ip(index,gte,lte,aggs_name,time_zone,querys_str)
    mylog.info('ES data size:%d '%len(ip_es_list))
    # 检查下载的网络情报
    if(filelist):
        try:
            #check each file and insert match results
            tmpThreatIP=checkAndInsert(path,filelist,ip_es_list,index,aggs_name,timestamp,serverNum,dport)
            # mylog.info('main_insert Threat_ip size:{}'.format(len(tmpThreatIP)))
            if(tmpThreatIP):
                allThreatIP=dict(allThreatIP,**tmpThreatIP)
        except Exception, e:
            mylog.error('check blacklist:{}'.format(e))
    else:
        mylog.warning('no files!')
    #blacklist match，本地黑名单检查
    blflg,blackpath=parser_config.get_self_filelist('blacklist')
    if(blflg==1):
        if(os.path.exists(blackpath)):
            filelist = get_all_file(blackpath)
            # 黑名单处理与普通文件不一样。
            # check each file
            for fname in filelist:
                fpath = blackpath + fname
                mylog.info(' -*-*-*-*- local file:{} -*-*-*-*-'.format(fname))
                dataset = blacklist_tools.load_blacklist(fpath)
                if (dataset):
                    try:
                        fullmatch, segmentmatch, subnetlpm, subnetfull = treatip(dataset, ip_es_list)
                        tmpIP=insert_result(index, aggs_name, timestamp, serverNum, dport, fullmatch, segmentmatch, subnetlpm,
                                  subnetfull, dataset)
                        if(tmpIP):
                            allThreatIP=dict(allThreatIP,**tmpIP)
                    except Exception,e:
                        mylog.error('check local blacklist:{}'.format(e))
        else:
            mylog.info('no self_blacklist_path')
    return allThreatIP


if __name__ == '__main__':
	main('tcp-*',sys.argv[1],sys.argv[2],'dip',sys.argv[3])
	main('udp-*',sys.argv[1],sys.argv[2],'dip',sys.argv[3])