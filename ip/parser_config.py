#! /usr/bin/python
# -*- coding:utf8 -*-
# author: songh

import sys
sys.path.append('..')
import ConfigParser
import datetime, os,json
from global_tools import set_logger

# ========read config =================
__conf_global = "../cfg/conf_global.json"
with open(__conf_global, 'r') as f:
    __conf_g = json.loads(f.read())
#print __conf
__conf_ip="../cfg/conf_ip.json"
with open(__conf_ip, 'r') as fs:
    __conf_ip = json.loads(fs.read())

cp = ConfigParser.ConfigParser()
cp.read("blacklist_match.conf")
section = cp.sections()


# print section
def get_func():
    #parse_blacklist_key = cp.options("parse_blacklist")
    # function module
    #moudle_func = cp.get("parse_blacklist", parse_blacklist_key[0])
    #moudle_list = moudle_func.split(',')
    # print moudle_list
    moudle_name = __conf_ip["blacklist_file"]
    # for temp in moudle_list:
    #     fname, ftimes = temp.split(":")
    #     fname = fname.strip()
    #     # as a dict: key is filename,value is the update frequency
    #     moudle_name[fname] = ftimes
    return moudle_name


def get_store_path():
    # source_data_path
    # source_store_path_key = cp.options('source_store_path')
    source_store_path = __conf_ip["file_path"]["store_path"]
    # for temp in source_store_path_key:
    #     source_store_path.append(cp.get('source_store_path', temp))
    return source_store_path


def get_ES_info():
    # ES information
    global_info=__conf_g["es_server"]
    ip_info=__conf_ip["ES_info"]
    # value=cp.get(sectionName,keyword)
    server = global_info["server"]
    dport = global_info["port"]
    indx = ip_info["index"]
    aggs_name = ip_info["aggs_name"]
    query_str = ip_info["query"]
    return server, dport, indx, aggs_name, query_str

def get_Alert_info():
    alert_indx=__conf_g["es_server"]["alert_index"]
    return alert_indx

def getCheckDeltatime():
    # check frequency
    # timekey1 = cp.options("delta_time_check")
    # times = cp.getint("delta_time_check", timekey1[0])
    times=__conf_g["time"]["interval"]
    deltatime = datetime.timedelta(minutes=times)
    # sec = cp.getint("delta_time_check", timekey1[1])
    sec=__conf_g["time"]["offset"]
    offset = datetime.timedelta(seconds=sec)
    # timekey2 = cp.options("frequency")
    # starttime = cp.get("frequency", timekey2[0])
    starttime=__conf_g["time"]["startTime"]
    return deltatime, starttime, offset


def get_bl_path():
    # source_data_path
    # module_path_key = cp.options('blacklist_moudle_path')
    # print module_path_key
    module_path = __conf_ip["file_path"]["blacklist_path"]
    # for temp in module_path_key:
    #     module_path.append(cp.get('blacklist_moudle_path', temp))
    return module_path


def get_method():
    # get subnet method
    # source_store_path_key = cp.options("subnet_methods")
    # value=cp.get(sectionName,keyword)
    # flg_lpm = cp.getint('subnet_methods', source_store_path_key[0])
    # flg_full = cp.getint('subnet_methods', source_store_path_key[1])
    flg_lpm=__conf_ip["switch"]["lpm_method"]
    flg_full=__conf_ip["switch"]["full_method"]
    return flg_lpm, flg_full


def get_self_filelist(keywords):
    # optionname must be whitelist or blacklist or defaultlist
    mylog = set_logger()
    optionname = 'self_' + keywords + '_path'
    optionflg=keywords+'_flg'
    try:
        # source_store_path_key = cp.options(optionname)
        paths = __conf_ip["file_path"]
        # value=cp.get(sectionName,keyword)
        # flg = cp.getint(optionname, source_store_path_key[0])
        # bpath = cp.get(optionname, source_store_path_key[1])
        flg=paths[optionflg]
        bpath=paths[optionname]
        path = get_store_path() + bpath + os.path.sep
        return flg, path
    except Exception, e:
        mylog.error('config file error!')
        return 0, ''


def get_ip_secondcheck():
    # get subnet method
    # source_store_path_key = cp.options("ip_second_check")
    # value=cp.get(sectionName,keyword)
    # ipSecondCheckC2 = cp.getint('ip_second_check', source_store_path_key[0])
    ipSecondCheckC2 = __conf_ip["switch"]["ip_check_C2"]
    return ipSecondCheckC2


def get_WarnLis_size():
    # get subnet method
    # source_store_path_key = cp.options("warnLis_size")
    # value=cp.get(sectionName,keyword)
    # lis_size = cp.getint('warnLis_size', source_store_path_key[0])
    lis_size=__conf_ip["switch"]["warnList"]
    return lis_size


def update_flg():
    # get subnet method
    # source_store_path_key = cp.options("update_flg")
    # value=cp.get(sectionName,keyword)
    # flg = cp.getint('update_flg', source_store_path_key[0])
    flg=__conf_ip["switch"]["update_flg"]
    return flg


# print cp.sections
# cun period
#############################################################################################################################
# frequency_key = cp.options(sections[3])
# frequency = []
# for temp in frequency_key:
#     frequency.append(cp.get('frequency', temp))
#
# # print frequency
# regex1=re.compile(r'\d+')
# regex2=re.compile(r'[a-zA-Z]+')
# period_num = regex1.findall(frequency[1])[0]
# period_scale = regex2.findall(frequency[1])[0]
# def export_period():
#     if period_scale == 's'or period_scale == 'S' :
#         period  = datetime.timedelta(seconds = int(period_num))
#     elif period_scale == 'm'or period_scale == 'M':
#         period = datetime.timedelta(minutes = int(period_num))
#     elif period_scale == 'd' or period_scale == 'D':
#         period = datetime.timedelta(days = int(period_num))
#     return period
#if __name__ == '__main__':
    #a, b, c, d, e = get_ES_info()
    # print e
#############################################################################################################################
