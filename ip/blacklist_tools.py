#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
sys.path.append('..')
import datetime, re, os, json, socket, struct
import lpm, parser_config
import logging
from logging.handlers import TimedRotatingFileHandler
from global_tools import set_logger


def judge_level(fp, status):
    '''
	根据fp、status判断level
	'''
    if status == 'online':
        if fp == 'high':
            return 'WARNING'
        else:
            return 'CRITICAL'
    elif status == 'unknown':
        if fp == 'low':
            return 'CRITICAL'
        elif fp == 'high':
            return 'INFO'
        else:
            return 'WARNING'
    else:
        if fp == 'low' or fp == 'unknown':
            return 'WARNING'
        else:
            return 'INFO'


def judge_unknown(str1, str2):
    '''
	两个情报源发现相同的domain时，整合情报，判断fp与status的值
	'''
    if str1 == str2:
        return str1
    elif str1 != 'unknown' and str2 != 'unknown':
        return 'unknown'
    elif str1 != 'unknown':
        return str1
    elif str2 != 'unknown':
        return str2


def judge_date(str1, str2):
    '''
	两个情报源发现相同的domain时，记录最近的时间整合情报
	'''
    if str1 == str2:
        return str1
    else:
        date1 = datetime.datetime.strptime(str1, '%Y-%m-%d')
        date2 = datetime.datetime.strptime(str2, '%Y-%m-%d')
        if date1 > date2:
            return date1.strftime('%Y-%m-%d')
        else:
            return date2.strftime('%Y-%m-%d')


def update_dict(dict1, dict2):
    '''
	合并两个字典
	'''
    domain_insection = set(dict1.keys()) & set(dict2.keys())
    print domain_insection
    ret_dict = dict(dict1, **dict2)
    if domain_insection:
        for domain in domain_insection:
            ret_type = dict1[domain]['type'] + ';' + dict2[domain]['type']
            ret_source = dict1[domain]['source'] + ';' + dict2[domain]['source']
            ret_status = judge_unknown(dict1[domain]['status'], dict2[domain]['status'])
            ret_fp = judge_unknown(dict1[domain]['fp'], dict2[domain]['fp'])
            ret_date = judge_date(dict1[domain]['date'], dict2[domain]['date'])
            ret_dict[domain] = {
                'type': ret_type,
                'date': ret_date,
                'source': ret_source,
                'status': ret_status,
                'fp': ret_fp
            }
    return ret_dict


def saveAsJSON(date, dict1, path, name):
    '''
	保存为json
	'''
    file_name = path + name + '-' + str(date) + '.json'
    try:
        with open(file_name, 'w') as f:
            f.write(json.dumps(dict1))
    except IOError:
        print 'saveAsJSON Error'


def temp_store(dict, name):
    '''
	保存为json
	'''
    tmp = name[-5:]
    if (tmp == '.json'):
        file_name = name
    else:
        file_name = name + '.json'
    try:
        with open(file_name, 'w') as f:
            f.write(json.dumps(dict))
    except IOError:
        print 'temp_store Error'


def load_dict(filedir):
    '''
	加载本地的json文件
	'''
    dict1 = {}
    try:
        with open(filedir, 'r') as f:
            dict1 = json.loads(f.read())
    except IOError:
        print 'load_dict Error'
    return dict1


def insert(Trie, element):
    '''
	将element插入Trie
	'''
    if element:
        item = element.pop()
        if item not in Trie:
            Trie[item] = {}
        Trie[item] = insert(Trie[item], element)
    return Trie


def create_Trie(blacklist):
    '''
	根据blacklist创建Trie
	'''
    domainTrie = {}
    for domain in blacklist:
        domainTrie = insert(domainTrie, domain)
    return domainTrie


'''
def getlog():
	mylog = logging.getLogger()
	if len(mylog.handlers) == 0:  # just only one handler
		level = logging.INFO
		filename = os.getcwd() + os.path.sep + 'data' + os.path.sep +'log'+ os.path.sep+ 'testlog'
		format = '%(asctime)s %(levelname)-8s: %(message)s'
		hdlr = TimedRotatingFileHandler(filename, "midnight", 1, 0)
		hdlr.suffix = "%Y%m%d.log"
		fmt = logging.Formatter(format)
		hdlr.setFormatter(fmt)
		mylog.addHandler(hdlr)
		mylog.setLevel(level)
	return mylog
'''


def load_whitelist(whitepath):
    mylog = set_logger()
    datadic = {}
    if (os.path.exists(whitepath)):
        # return  dataset,and type is dict
        with open(whitepath, 'r') as bf:
            allip = bf.read().split(',')
            for ips in allip:
                datadic[ips] = {
                    'subtype': 'whitelist',
                    'desc_subtype': 'local whitelist ip'
                }
    else:
        mylog.warn('[mal_ip] NO whitelist path!')
    return datadic

# 利用intel_source/source.rule更新local_bl，即更新替换
# def update_bl():
#     intldata=read_intel()
#     lcl_bl={}
#     for itm in intldata:
#         #itm is dict
#         if(len(itm['ip'])):
#             ips=itm['ip']
#             # 若无值，则default 处理
#             if(not len(itm["type"])):
#                 itm["type"]="suspect"
#             if (not len(itm["source"])):
#                 itm["source"] = "local_intelligence"
#             for i in ips:
#                 lcl_bl[i] = {
#                     'subtype': itm['type'],
#                     'desc_subtype': '{0} ip; source:{1}'.format(itm['type'], itm['source']),
#                     'level': 'info',
#                     'mapping_ip': i,
#                 }
#     return lcl_bl

# 加载本地黑名单步骤
'''
step1: local_bl与intel_source下source.rule比较修改时间；
    若两者更新时间相差1小时以上，则更新local_bl
    若没有，则直接使用local_bl
step2：更新local_bl的过程：
    读source.rule，提取ip,构造json结构；
    将json结构存入local_bl
'''
# def load_blacklist(blackpath):
#     mylog = set_logger()
#     # intel path
#     intlp=get_intel_path()
#     datadic = {}
#     if (os.path.exists(blackpath) and os.path.exists(intlp)):
#         # return  dataset,and type is dict
#         # compare time
#         if (cmp_file_mtime(blackpath, intlp)):
#             # intlp time> blackpath time ,update local bl
#             datadic=update_bl()
#             # 覆盖原local_bl文件
#             time.sleep(1)
#             try:
#                 with open(blackpath,'w') as fp:
#                     json.dump(datadic,fp)
#             except Exception,e:
#                 mylog.error('[mal_ip] save local blacklist error :{}'.format(e))
#         else:# 不更新，直接用local_bl
#             try:
#                 with open(blackpath,'r') as fp:
#                     datadic=json.load(fp,encoding='utf-8')
#             except Exception,e:
#                 mylog.error('[mal_ip] Load local blacklist error :{}'.format(e))
#     elif(os.path.exists(blackpath)):
#         # no intel_source/source.rule, use the local_bl
#         try:
#             with open(blackpath, 'r') as fp:
#                 datadic = json.load(fp, encoding='utf-8')
#         except Exception, e:
#             mylog.error('[mal_ip] Load local blacklist error :{}'.format(e))
#     elif(os.path.exists(intlp)):
#         # no local_bl, update
#         datadic = update_bl()
#         # 覆盖原local_bl文件
#         time.sleep(1)
#         try:
#             with open(blackpath, 'w') as fp:
#                 json.dump(datadic, fp)
#         except Exception, e:
#             mylog.error('[mal_ip] save local blacklist error :{}'.format(e))
#     else:
#         mylog.warn('[mal_ip] all blacklists are not existed !')
#     return datadic


# ============ global module   ============================
def global_init():
    global _global_dic
    _global_dic = {}


def set_global_value(name, value):
    _global_dic[name] = value


def get_global_value(name):
    try:
        return _global_dic[name]
    except Exception, e:
        return None


# ======================================================

# ip格式分割
def separate_ip(ipdict):
    regex1 = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    regex2 = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    regex3 = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$')
    iplist = ipdict.keys()
    full_match = {}
    segment = {}
    subnet = {}
    for ip_element in iplist:
        if regex1.match(ip_element):
            full_match[ip_element] = ipdict[ip_element]
        elif regex2.match(ip_element):
            segment[ip_element] = ipdict[ip_element]
        elif regex3.match(ip_element):
            subnet[ip_element] = ipdict[ip_element]
    return full_match, segment, subnet


# ip按'.'分割成数组
def ip_split_num(ip):
    ip_num = ip.split('.')
    for i in range(len(ip_num)):
        ip_num[i] = int(ip_num[i])
    return ip_num


# 白名单过滤
def whitelist_filter(fullmatch, segmentmatch, lpmmatch, lpmfullmatch, whitelist):
    # treat whitelist data
    white_full, white_segment, white_subnet = separate_ip(whitelist)
    # filter each match result
    lpm.init()
    for sn in white_subnet:
        subnet_split = sn.split('/')
        ip_num = ip_split_num(subnet_split[0])
        netMask = int(subnet_split[1])
        if (sn == '192.168.0.0/16' or sn == '172.16.0.0/12' or sn == '10.0.0.0/8'):  # 略过私网
            continue
            # return 'False'
        elif (netMask == 16):
            newip1 = []
            ip_num[2] = ip_num[2] | 1
            newip1.append(str(ip_num[0]))
            newip1.append(str(ip_num[1]))
            newip1.append('*')
            newip1.append('*')
            ipstr1 = '.'.join(newip1)
            lpm.insert_rule(ipstr1)
        elif (netMask == 24):
            # /24处理
            newip1 = []
            newip1.append(str(ip_num[0]))
            newip1.append(str(ip_num[1]))
            newip1.append(str(ip_num[2]))
            newip1.append('*')
            ipstr1 = '.'.join(newip1)
            lpm.insert_rule(ipstr1)
        else:
            # netMask>16 and not in [16,23,24,25],save them
            continue
    fullmatch_set = set(fullmatch) - (set(fullmatch) & set(white_full))
    matchlist = []
    for ips in fullmatch_set:
        ip_es_num = socket.ntohl(struct.unpack("I", socket.inet_aton(str(ips)))[0])
        if (lpm.search_ip(ip_es_num)):
            matchlist.append(ips)
    fullmatch = list(fullmatch_set - set(matchlist))
    # subnet
    tmpmatch = []
    if (len(lpmmatch) > 0):
        for i in lpmmatch:
            ips = i.keys()[0]
            ip_es_num = socket.ntohl(struct.unpack("I", socket.inet_aton(str(ips)))[0])
            if (ips in white_full or lpm.search_ip(ip_es_num)):
                tmpmatch.append(i)
        for ii in tmpmatch:
            lpmmatch.remove(ii)

    return fullmatch, segmentmatch, lpmmatch, lpmfullmatch


def subnet_to_binary(num):
    nm_binary = num * '1' + (32 - num) * '0'
    # socket.inet_ntoa(struct.pack('I',socket.ntohl(int(nm_binary,2)))).split('.')  -> nm_num
    nm_num = []
    for i in range(4):
        temp = nm_binary[8 * (i):8 * (i + 1)]
        ip_pot = 0
        for j in range(len(temp)):
            ip_pot = ip_pot + (int(temp[j]) * (2 ** (7 - j)))
            if j == 7:
                nm_num.append(int(ip_pot))
    return nm_num


# change subnet to range，将'/24'等子网段形式转换成“A-B"形式
def subnet_range(subnet):
    subnet_split = subnet.split('/')
    ip_num = ip_split_num(subnet_split[0])
    netMask = int(subnet_split[1])
    nm_num = subnet_to_binary(netMask)
    firstadr = []
    lastadr = []
    ip_range = []
    if netMask == 31:
        firstadr.append(str(ip_num[0] & nm_num[0]))
        firstadr.append(str(ip_num[1] & nm_num[1]))
        firstadr.append(str(ip_num[2] & nm_num[2]))
        firstadr.append(str(ip_num[3] & nm_num[3]))

        lastadr.append(str(ip_num[0] | (~ nm_num[0] & 0xff)))
        lastadr.append(str(ip_num[1] | (~ nm_num[1] & 0xff)))
        lastadr.append(str(ip_num[2] | (~ nm_num[2] & 0xff)))
        lastadr.append(str(ip_num[3] | (~ nm_num[3] & 0xff)))
        begin_addr = '.'.join(firstadr)
        end_addr = '.'.join(lastadr)
        begin_int = socket.ntohl(struct.unpack("I", socket.inet_aton(begin_addr))[0])
        end_int = socket.ntohl(struct.unpack("I", socket.inet_aton(end_addr))[0])
        ip_range.append(begin_int)
        ip_range.append(end_int)

    elif netMask == 32:
        firstadr.append(str(ip_num[0]))
        firstadr.append(str(ip_num[1]))
        firstadr.append(str(ip_num[2]))
        firstadr.append(str(ip_num[3]))

        lastadr.append(str(ip_num[0]))
        lastadr.append(str(ip_num[1]))
        lastadr.append(str(ip_num[2]))
        lastadr.append(str(ip_num[3]))
        begin_addr = '.'.join(firstadr)
        end_addr = '.'.join(lastadr)
        begin_int = socket.ntohl(struct.unpack("I", socket.inet_aton(begin_addr))[0])
        end_int = socket.ntohl(struct.unpack("I", socket.inet_aton(end_addr))[0])
        ip_range.append(begin_int)
        ip_range.append(end_int)
    else:
        lastadr.append(str(ip_num[0] | (~ nm_num[0] & 0xff)))
        lastadr.append(str(ip_num[1] | (~ nm_num[1] & 0xff)))
        lastadr.append(str(ip_num[2] | (~ nm_num[2] & 0xff)))
        lastadr.append(str((ip_num[3] | (~ nm_num[3] & 0xff)) - 1))

        firstadr.append(str(ip_num[0] & nm_num[0]))
        firstadr.append(str(ip_num[1] & nm_num[1]))
        firstadr.append(str(ip_num[2] & nm_num[2]))
        firstadr.append(str((ip_num[3] & nm_num[3]) + 1))
        begin_addr = '.'.join(firstadr)
        end_addr = '.'.join(lastadr)
        begin_int = socket.ntohl(struct.unpack("I", socket.inet_aton(begin_addr))[0])
        end_int = socket.ntohl(struct.unpack("I", socket.inet_aton(end_addr))[0])
        ip_range.append(begin_int)
        ip_range.append(end_int)

    return ip_range


# 循环处理子网转成”A-B"形式
def subnetTOrange(sn24):
    mylog=set_logger()
    allRange = {}
    #mylog.info("type_1:{0}".format(type(allRange)))
    for subnets in sn24:
        allRange[subnets] = subnet_range(subnets)
        # return {key:[start,end],...}
    return allRange


# zhou
# focus on gte24 data,处理大于‘/24’的子网段
# Firstly, change gte24 to range type
# Secondly, match by range method
def subnet_range_match(sn_gte24, es_ip):
    sn_gte24_list = []
    mylog = set_logger()
    # firstly,
    # mylog.info("len of gte24:{0}".format(len(sn_gte24)))
    allrange = subnetTOrange(sn_gte24)
    #mylog.info("type:{0}".format(type(allrange)))
    # secondly, match
    # mylog.info('gte24 size:{}'.format(len(sn_gte24)))
    # sorted
    newAllRange = sorted(allrange.iteritems(), key=lambda x: x[1][0])
    rangeLen = len(newAllRange)
    # mylog.info('start Binary Search!')
    for ips in es_ip:
        ip_es_num = socket.ntohl(struct.unpack("I", socket.inet_aton(str(ips)))[0])
        # Binary Search
        nlow = 0
        nhigh = rangeLen - 1
        while (nlow <= nhigh):
            nmid = (nlow + nhigh) / 2
            subnet_num = newAllRange[nmid][1]  # [start,end]
            if (subnet_num[0] <= ip_es_num <= subnet_num[1]):
                sn_gte24_list.append({ips: newAllRange[nmid][0]})
                break
            elif (subnet_num[0] > ip_es_num):
                nhigh = nmid - 1
            elif (subnet_num[1] < ip_es_num):
                nlow = nmid + 1
    return sn_gte24_list


# 设置存储路径
def getsavepath(fpath, name):
    tday = datetime.datetime.now().date()
    file_name = fpath + name + '_' + str(tday) + '.json'
    return file_name


def saveToJSON(dict1, path, name):
    "add the subnet to file"
    # mylog=getlog()
    file_name = getsavepath(path, name)
    try:
        with open(file_name, 'w') as f:
            f.write(json.dumps(dict1))
    except IOError:
        print 'save Error'
        # mylog.error('saveToJSON Error!')


# ip is string for single xxx.xxx.xxx.xxx/XX, subnet is number
# lpm比较，将subnet格式再细分，然后调用lpm
def subnet_lpm(subnet, es_ip):
    mylog = set_logger()
    lpm.init()
    sndict = {}
    fpath = parser_config.get_store_path()
    sn_lte16 = {}
    lpmdict = {}
    sn_gte24 = {}
    ip_subnet = subnet.keys()
    # mylog.info("subnetlpm size:{0}".format(len(ip_subnet)))
    for sn in ip_subnet:
        subnet_split = sn.split('/')
        ip_num = ip_split_num(subnet_split[0])
        netMask = int(subnet_split[1])
        if (sn == '192.168.0.0/16' or sn == '172.16.0.0/12' or sn == '10.0.0.0/8'):  # 略过私网
            continue
            # return 'False'
        elif (netMask < 16):  # 暂时不处理
            sn_lte16[sn] = subnet[sn]
            # return 'False'
        elif (netMask == 16):
            lpmdict[sn] = subnet[sn]
            newip1 = []
            ip_num[2] = ip_num[2] | 1
            newip1.append(str(ip_num[0]))
            newip1.append(str(ip_num[1]))
            newip1.append('*')
            newip1.append('*')
            ipstr1 = '.'.join(newip1)
            lpm.insert_rule(ipstr1)
        elif (netMask >= 21 and netMask <= 24):
            lpmdict[sn] = subnet[sn]
            idx = pow(2, 24 - netMask) - 1
            # print idx
            ip_base = ip_num[2] & (255 - idx)
            i = 0
            while (i <= idx):
                newip1 = []
                ipstr1 = ''
                ip_num[2] = ip_base + i
                newip1.append(str(ip_num[0]))
                newip1.append(str(ip_num[1]))
                newip1.append(str(ip_num[2]))
                newip1.append('*')
                ipstr1 = '.'.join(newip1)
                # print ipstr1
                lpm.insert_rule(ipstr1)
                i = i + 1
        # elif(netMask==24):
        #     #/25当/24处理
        #     lpmdict[sn] = subnet[sn]
        #     newip1 = []
        #     newip1.append(str(ip_num[0]))
        #     newip1.append(str(ip_num[1]))
        #     newip1.append(str(ip_num[2]))
        #     newip1.append('*')
        #     ipstr1 = '.'.join(newip1)
        #     lpm.insert_rule(ipstr1)
        elif (netMask > 24):  # range match
            sn_gte24[sn] = subnet[sn]
        else:
            # netMask>16 and netMask<21,save them
            sndict[sn] = subnet[sn]
    #mylog.info('lpm data size: %d' % len(lpmdict))
    #mylog.info('remaining subnet size:%d' % len(sndict))
    #mylog.info('lte16 size:%d' % len(sn_lte16))
    #mylog.info('gte24 size:%d' % len(sn_gte24))
    # save
    snpath = getsavepath(fpath, 'remaining_subnet')
    ltepath = getsavepath(fpath, 'lte16_subnet')
    lpmpath = getsavepath(fpath, 'lpm_subnet_data')
    gtepath = getsavepath(fpath, 'gte24_subnet')
    if (sndict):
        if (os.path.exists(snpath)):
            newsndict = load_dict(snpath)
            newsndict1 = dict(newsndict, **sndict)  # merge
            saveToJSON(newsndict1, fpath, "remaining_subnet")
        else:
            saveToJSON(sndict, fpath, "remaining_subnet")
    if (sn_lte16):
        if (os.path.exists(ltepath)):
            newlte = load_dict(ltepath)
            newlte16 = dict(newlte, **sn_lte16)  # merge
            saveToJSON(newlte16, fpath, 'lte16_subnet')
        else:
            saveToJSON(sn_lte16, fpath, 'lte16_subnet')
    if (lpmdict):
        if (os.path.exists(lpmpath)):
            newlpmdict = load_dict(lpmpath)
            newlpmdict1 = dict(newlpmdict, **lpmdict)  # merge
            saveToJSON(newlpmdict1, fpath, 'lpm_subnet_data')
        else:
            saveToJSON(lpmdict, fpath, 'lpm_subnet_data')
    if (sn_gte24):
        if (os.path.exists(gtepath)):
            newlpmdict = load_dict(gtepath)
            newlpmdict1 = dict(newlpmdict, **sn_gte24)  # merge
            saveToJSON(newlpmdict1, fpath, 'gte24_subnet')
        else:
            saveToJSON(sn_gte24, fpath, 'gte24_subnet')
    sn_gte24 = dict(sn_gte24, **sndict)  # merge
    # match
    subnet_result = []
    for ips in es_ip:
        ip_es_num = socket.ntohl(struct.unpack("I", socket.inet_aton(str(ips)))[0])
        if (lpm.search_ip(ip_es_num)):
            subnet_result.append({ips: 'subnet_lpm_match'})
    return subnet_result, sndict, sn_lte16, sn_gte24


# 全匹配
def ip_full_match(full_list, ip_es_list):
    match_result = set(full_list) & set(ip_es_list)
    return list(match_result)


# segment比较
def ip_segment_match(num_iprange, ip_es):
    ip_es_num = socket.ntohl(struct.unpack("I", socket.inet_aton(str(ip_es)))[0])
    for ip_range in num_iprange.keys():
        # print ip_range[0], ip_range[1]
        if (long(num_iprange[ip_range]["start"]) <= ip_es_num <= long(num_iprange[ip_range]["end"])):
            return {ip_es: ip_range}
        # if ip_range[0] <= ip_es_num <=ip_range[1]:
        #     return ip_es
    return False


# 构造并调用segment比较
def int_ip_range(segment, es_ip):
    # segment
    ip_segment = segment.keys()
    ip_int = {}
    for element in ip_segment:
        ip_int[element] = {}
        ip_num = []
        ip_segment = element.split('-')
        A = ip_segment[0]
        B = ip_segment[1]
        num_ip_A = socket.ntohl(struct.unpack("I", socket.inet_aton(str(A)))[0])
        num_ip_B = socket.ntohl(struct.unpack("I", socket.inet_aton(str(B)))[0])
        ip_int[element]["start"] = num_ip_A
        ip_int[element]['end'] = num_ip_B
        # ip_num.append(num_ip_A)
        # ip_num.append(num_ip_B)
        # ip_int.append(ip_num)
    # match
    segment_match = []
    for ip_str in es_ip:
        flg = ip_segment_match(ip_int, ip_str)  # flg={ip:range} or False
        if (flg):
            segment_match.append(flg)  # segment_match=[{ip,range},{},{}...]
    return segment_match
