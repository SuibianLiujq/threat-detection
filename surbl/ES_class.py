#!/usr/bin/python
# -*- coding:utf8 -*-
# @Time    : 2018/11/21 10:43
# @Author  : songh
# @File    : ES_class.py
# @Software: PyCharm
from elasticsearch import Elasticsearch
import datetime

class ESClient(object):
    def __init__(self,iserver="localhost",iport='9200'):
        self._es_client_=Elasticsearch([{"host":iserver,"port":iport}])
    # def get_data_ssh(self,indx,es_sip,es_dip,es_dport,gte,lte,izone):
    #     search_option={
    #         "size": 5000,
    #         "query": {
    #             "bool":{
    #                 "must":[
    #                     {"term":{"sip": es_sip}},
    #                     {"term":{"dip":es_dip}},
    #                     {"term":{"dport":es_dport}},
    #                     {"term": {"timeout_state_num":8}},
    #                     {
    #                         "range": {
    #                             "@timestamp": {
    #                                 "gte": gte,
    #                                 "lte": lte,
    #                                 "format": "yyyy-MM-dd HH:mm:ss",
    #                                 "time_zone": izone
    #                             }
    #                         }
    #                     }
    #                 ]
    #             }
    #         },
    #         "_source": {
    #             "includes": ["inpacket","retransmit_in","outpacket","retransmit_out","inbyte","outbyte"]
    #         }
    #         # "aggs": {
    #         #     "ssh": {
    #         #         "date_histogram": {
    #         #             "field": "@timestamp",
    #         #             "interval": "1m",
    #         #             "min_doc_count": 1
    #         #         }
    #         #     }
    #         # }
    #     }
    #     search_result = self._es_client_.search(
    #         index=indx,
    #         body=search_option
    #     )
    #     tmp_result=search_result["hits"]["hits"]
    #     return tmp_result

    def get_dns_data(self,indx,gte,lte,izone):
        # iquery="sip:{0} AND dip:{1} AND dprot:{2} AND unknown_conn:0".format(es_sip,es_dip,es_dport)
        iquery='domain:*.multi.surbl.org AND isresponse:1 AND retcode:0'
        search_option={
            "size": 5000,
            "query": {
                "bool":{
                    "must":[
                        {
                            "query_string": {
                                "query": iquery,
                                "analyze_wildcard": True
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "yyyy-MM-dd HH:mm:ss",
                                    "time_zone": izone
                                }
                            }
                        }
                    ]
                }
            },
            "_source": {
                "includes": ["domain","answer"]
            }
        }
        search_result = self._es_client_.search(
            index=indx,
            body=search_option
        )
        tmp_result=search_result["hits"]["hits"]
        return tmp_result
    # doc is alert infomation,indx is alert_index
    def es_index(self,doc,indx):
        '''
        数据回插es的alert-*索引
        '''
        ret = self._es_client_.index(
            index='{0}-{1}'.format(indx,datetime.datetime.now().strftime('%Y-%m-%d')),
            doc_type='netflow_v9',
            body=doc
        )


'''
# for examples:
es = ESClient(server="172.23.2.199",port="9200")
ssh_data=es.get_data_ssh()
'''
