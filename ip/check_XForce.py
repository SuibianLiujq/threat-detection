#! /usr/bin/python
# -*- coding:utf8 -*-
# author: songh
'''
this file constructs a function to get infomation from IBM X-Force
now this file is independent
'''
from requests.auth import HTTPBasicAuth
import time,requests
# import urllib2
# from bs4 import BeautifulSoup as bs
# from selenium import webdriver
# import blacklist_tools
import os,datetime
import json

# define  ===============================================
# 预定义
ky='d922f0d8-9c63-4de3-b81c-f88ff0bbe182'
pw='610203ed-f7eb-4d0d-b3a5-9d33c5f20ff7'
#host_ibm='https://exchange.xforce.ibmcloud.com/api'
host_ibm='https://api.xforce.ibmcloud.com'
# https://exchange.xforce.ibmcloud.com/api/ipr/198.54.117.200
# # https://api.xforce.ibmcloud.com/ipr/198.54.117.200
# https://exchange.xforce.ibmcloud.com/api/url/xmodapk.org
search_type={
    1:'ipr',
    2:'url'
}
# file path = './data/XForce-year-month.json'
lpath=os.getcwd()+os.path.sep+'data'+os.path.sep
mydate=datetime.datetime.now()
months=str(mydate.year)+'-'+str(mydate.month)
filename='XForce-{0}.json'.format(months)
#====================================================
def load_dict(filedir):
	'''
	加载本地的json文件
	'''
	dict1={}
	try:
		with open(filedir,'r') as f:
			dict1=json.loads(f.read())
	except IOError:
		print 'load_dict Error'
	return dict1

def temp_store(dict,name):
	'''
	保存为json
	'''
	tmp=name[-5:]
	if(tmp=='.json'):
		file_name=name
	else:
		file_name = name+ '.json'
	try:
		with open(file_name,'w') as f:
			f.write(json.dumps(dict))
	except IOError:
		print 'temp_store Error'


def bydefaut_struct(names):
    results={}
    results[names]={
        "rank":0,
        "categories":{
        },
        "site":{}
    }
    return results

def dic_ip(txt):
    # analysis ip_json per search result
    # txt : return data(json)
    single_ip={}
    if (len(txt.keys()) == 0):
        print "no return data."
    elif(txt.has_key('error')):
        # error!
        print txt['error']
    else:
        if(txt.has_key('ip')):
            iptmp=txt['ip']
        else:
            print 'no key name ip'
            return single_ip
        single_ip[iptmp]={}
        if (txt.has_key('score')):
            single_ip[iptmp]['score'] = txt['score']
        else:
            single_ip[iptmp]['score'] = 0
        if (txt.has_key('cats')):
            single_ip[iptmp]['cats'] = txt['cats']
        else:
            single_ip[iptmp]['cats'] = {}
        # subnet
        if (txt.has_key('subnets')):
            subnet = txt['subnets']  # list
            subnet_json = subnet[0]
            if(subnet_json.has_key('geo') and subnet_json['geo'].has_key('country')):
                single_ip[iptmp]['geo'] = subnet_json['geo']['country']
            else:
                single_ip[iptmp]['geo'] = ''
            if(subnet_json.has_key('asns')):
                asnstmp = subnet_json['asns'].keys()
                if(len(asnstmp)==1):
                    single_ip[iptmp]['asns'] = asnstmp[0]
                    if(subnet_json['asns'][asnstmp[0]].has_key('Company')):
                        single_ip[iptmp]['company'] = subnet_json['asns'][asnstmp[0]]['Company']
                    else:
                        single_ip[iptmp]['company'] =''
                else:
                    single_ip[iptmp]['asns']=''
    return single_ip

def dic_url(txt):
    # analysis url_json per search result
    # txt : return data(json)
    single_url={}
    if(len(txt.keys())==0):
        print "no return data."
    elif (txt.has_key('error')):
        # error!
        print txt['error']
    else:
        re_tmp=txt['result']
        urltmp=re_tmp['url']
        single_url[urltmp]={}
        single_url[urltmp]['cats']=re_tmp['cats']
        single_url[urltmp]['score']=re_tmp['score']
    return single_url

def get_info(host,type,value):
    # host= host_ibm; type = url or ip;
    # # return json: {"value":{"rank":int(grades),"categories":{'1':'marks','2':'marks',...}}}
    full_url=host+'/'+type+'/'+value
    #full_url=host[:-4]
    #get html
    #get_html(full_url)
    #  确保session使用后会关闭，减少http连接次数
    with requests.Session() as s:
        http = s.get(full_url, timeout=30,auth=HTTPBasicAuth(ky,pw))
        html_json = http.json()
    # http = requests.get(full_url, timeout=30,auth=HTTPBasicAuth(ky,pw))
    # html_txt = http.text
    # ss.keep_alive = False
    # process the json depend on type
    if(type=='ipr'):
        res=dic_ip(html_json)
    elif(type=='url'):
        res=dic_url(html_json)
    else:
        print 'type error!'

    return res

'''
# values : a list of ips or urls
# 
'''
def start(stype,values,checkflg=1):
    # 程序入口， checkflg表示是否检查和写入本地文件，默认值为1表示检查和写入。
    final_dic = {}# return
    if(not type(values)==list):# values is not list
        print 'values type error!'
        return final_dic
    # first step: check the local file
    if(checkflg==1):
        # load data from local file
        if(not os.path.exists(lpath)):# not exists,then create dir
            os.mkdir(lpath)
        fpath=lpath+filename
        if(os.path.exists(fpath)):
            ldic=load_dict(fpath)
            ldata=ldic.keys()#all ips and urls
        else:
            ldic={}
            ldata=[]# 写文件时再创建
        indic=set(values)&set(ldata)# 交集
        for ii in indic:
            final_dic[ii]=ldic[ii]
        outvalues=list(set(values)-set(ldata))# 差集,不在文件里

    # second step: remains data check the X-Force
    ftype=search_type[stype]
    tmp_dic={}
    for value in outvalues:
        try:
            resdata=get_info(host_ibm,ftype,value)# resdata is dic
            for tmp in resdata.keys():
                tmp_dic[tmp]=resdata[tmp]
        except Exception,e:
            if("ReadTimeout" in e):
                time.sleep(2)
                # retry
                try:
                    resdata = get_info(host_ibm, ftype, value)  # resdata is dic
                    for tmp in resdata.keys():
                        tmp_dic[tmp] = resdata[tmp]
                except Exception, e:
                    print(e)
                    continue
            else:
                print(e)
                continue

    if(checkflg==1):#merge into local file
        ldic=dict(ldic,**tmp_dic)
        # save
        temp_store(ldic,fpath)
    #merge result
    final_dic=dict(final_dic,**tmp_dic)
    # print json.dumps(final_dic,indent=4)
    return final_dic


if __name__ == '__main__':
    # for examples:
    # stype=1
    # value=['213.186.33.5','151.80.144.253']
    stype=2
    value=["lookingforgood.su"]
    '''
    {
        "binien.com": {
            "cats": {
                "Spam URLs": true
            }, 
            "score": 10
        }
    }
    '''
    start(stype,value)
