#!/usr/bin/python
# -*- coding: utf-8 -*-

import json
import datetime

def query_last(es,gte,lte,time_zone,dip):
	search_option = {
		"size": 0,
		"query": {
			"bool": {
				"must": [
					{
						"query_string": {
							"query": "unknown_conn:0 AND dip:{0}".format(dip),
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
					"size": 100,
					"order": {
						"_count": "desc"
					}
				}
			}
		}
	}
	result = es.search(
		index = "tcp-*",
		body  = search_option
	)
	return result

def get_date_flow(es,gte,lte,time_zone,dip,sip_list):
	search_option = {
		"size": 0,
		"query": {
			"bool": {
				"must": [
					{
						"query_string": {
							"query": "unknown_conn:0 AND dip:{0}".format(dip),
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
					"size": 100,
					"include":sip_list,
					"order": {
						"flow": "desc"
					}
				},
				"aggs":{
					"flow": {
						"sum": {
							"field": "flow"
						}
					},
					"date": {
						"date_histogram": {
							"field": "@timestamp",
							"interval": "5m",
							"time_zone":time_zone,
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
		index = "tcp-*",
		body  = search_option
	)
	return result

def calc_median(datalist):
	datalist.sort()
	half = len(datalist) // 2
	return (datalist[half]+datalist[~half])/2.0

def calc_MAD(datalist):
	median = calc_median(datalist)
	return calc_median([ abs(data-median) for data in datalist ])
	
def main(es,gte,lte,time_zone,dip):
	# 根据第一次检查的结果，获取当前时间的指定 dip 的 TCP 连接的所有 sip ，得到 sip_list
	result = query_last(es=es,gte=gte,lte=lte,time_zone=time_zone,dip=dip)
	sip_list = []
	for sip in result["aggregations"]["sip"]["buckets"]:
		sip_list.append(sip["key"])

	# 检查的时间范围扩大到 72h
	temp_lte = datetime.datetime.strptime(lte,'%Y-%m-%d %H:%M:%S')
	gt = (temp_lte - datetime.timedelta(hours = 72)).strftime('%Y-%m-%d %H:%M:%S')
	# 根据 dip 和 sip_list 进行过滤，按每个 sip 每 5m 聚合，获取每组 sip-dip 的流量的时间序列
	res = get_date_flow(es=es,gte=gt,lte=lte,time_zone=time_zone,dip=dip,sip_list=sip_list)

	ret_siplist = []
	# 循环对每组 sip-dip 进行分析
	for sip_item in res["aggregations"]["sip"]["buckets"]:
		# 该组 sip-dip 的数据量太小则不再进一步分析
		if len(sip_item["date"]["buckets"])<3:
			continue

		# 将流量的时间序列拆分成流量列表 flowlist 和日期列表 datelist	
		datelist = []
		flowlist = []
		for item in sip_item["date"]["buckets"]:
			datelist.append(item["key"])
			flowlist.append(item["flow"]["value"])
		# 计算日期列表 datelist 相邻两个时间戳的时间差，获得时间差列表 date_dev
		date_dev = [datelist[i+1]-datelist[i]  for i in range(len(datelist)-1)]
		# 当且仅当时间差列表 date_dev 及流量列表 flowlist 各自的数据超过一半相等，即 date_dev 和 flowlist 的 MAD 均为 0 时，认为该组 sip-dip 之间的通讯是有规律的 
		if (calc_MAD(date_dev) == 0) and (calc_MAD(flowlist) == 0):
			ret_siplist.append(sip_item["key"])
	return ret_siplist		
