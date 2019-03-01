#! /usr/bin/python
# -*- coding: utf-8 -*-
import logging,logging.handlers
from cloghandler import ConcurrentRotatingFileHandler
import re,platform,os,json,datetime,time
from IPy import IP
import ipdb

# split file and path
__conf_dir = os.path.join(os.path.split(__file__)[0],"../cfg/conf_global.json")
with open(__conf_dir,'r') as f:
	__conf = json.loads(f.read())

def platform_detection():
	pattern_platform = re.compile("^[^-]*")
	return pattern_platform.findall(platform.platform())[0]

def set_logger():
	log_level = __conf["log"]["level"].upper()
	log_path = os.path.abspath(os.path.join(os.path.split(__file__)[0],"../logs/threat-detection"))
	log_size = 4*1024*1024

	log = logging.getLogger("threat_intelligence")
	
	if len(log.handlers) == 0:
		rotate_handler = ConcurrentRotatingFileHandler( log_path, "a", log_size, 5)

		if log_level == "DEBUG":
			log.setLevel(logging.DEBUG)
		elif log_level == "INFO":
			log.setLevel(logging.INFO)
		elif log_level == "WARNING":
			log.setLevel(logging.WARNING)
		elif log_level == "ERROR":
			log.setLevel(logging.ERROR)
		else:
			raise ValueError,"logLevel should be DEBUG/INFO/WARNING/ERROR."

		# set logs formatter
		formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
		rotate_handler.setFormatter(formatter)

		# add handler to logger
		log.addHandler(rotate_handler)

	return log

def get_es_config():
	#ES configuration
	return __conf["es_server"]

def get_es_client():
	#ES configuration
	es_client = __conf["es_client"]
        
	if es_client["enable"]:
		return es_client
	else:
		return False

def get_syslog_config():
	syslog = __conf["syslog"]
	if not syslog["enable"]:
		return False

	logger_alert = logging.getLogger("MAL_DNS")
	logger_alert.setLevel(logging.INFO)
	alert_handler = logging.handlers.SysLogHandler((syslog["host"],syslog["port"]),logging.handlers.SysLogHandler.LOG_AUTH)
	formatter = logging.Formatter('%(message)s')
	alert_handler.setFormatter(formatter)
	logger_alert.addHandler(alert_handler)
	
	return logger_alert

def get_time_config():
	time_config = __conf["time"]

	if time_config["startTime"] == "now":
		time_config["startTime"] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

	return {
		"startTime": time_config["startTime"],
		"interval": datetime.timedelta(minutes = time_config["interval"]),
		"offset": datetime.timedelta(seconds = time_config["offset"])
	}

# get local intel_source file path
def get_intel_path():
	# ./security/ccbots/intel_source/source.rule
	fpath = os.path.join(os.path.split(__file__)[0], "../../intel_source/source.rule")
	return fpath

# read intel_source file
# def read_intel():
# 	fpath=get_intel_path()
# 	# get modified time
# 	# mt = time.ctime(os.stat(fpath).st_mtime)
# 	all_lis = []
# 	with open(fpath, "r") as fp:
# 		times = 0
# 		while 1:
# 			fline = fp.readline()
# 			b = fline.replace("\n", "")
# 			try:
# 				b=b.strip()
# 				c = json.loads(b[0:-1], encoding="utf-8")
# 				#print type(c)
# 				all_lis.append(c)
# 			except Exception, e:
# 				if (b == ''):
# 					break
# 	return all_lis


# 比较两个文件的更新时间,(remote-local)大于deltaT（单位秒，默认值1）则返回True;
# localfile：本地文件路径； remotefile：远程文件路径; deltaT: 时间差;
def cmp_file_mtime(localfile,remotefile,deltaT=1):
	lmt=time.mktime(time.gmtime(os.stat(localfile).st_mtime))
	rmt=time.mktime(time.gmtime(os.stat(remotefile).st_mtime))
	if(lmt>rmt):# local>remote
		return False
	elif(int(rmt-lmt)>deltaT):# remote-local>deltaT
		return True
	else:
		return False


# get local ip segment info
def get_local_ipsegment():
	local_ipseg = __conf["local_ip_segment"]
	return local_ipseg


# 查 sip 部门信息
def get_sip_dpInfo(sip,iplist):
	for keys,vals in iplist.items():
		if(sip in IP(keys)):
			return vals
	return "unknown"


# get ipip dataset path
def get_ipipGeo_path():
	fpath= __conf["ipipGeo"]
	return fpath

# 利用IP IP库查询地理位置,接受参数 为单个ip 或 ip list
# 注意编码格式： 输入是str或str list,而得到的结果是unicode编码。
def ipipCheckGeo(ips):
	mylog=set_logger()
	iplis = []
	# ipip查询仅接受unicode编码
	if(type(ips) is unicode):
		iplis.append(ips)
	elif(type(ips) is str):
		iplis.append(ips)
	elif(type(ips) is list):
		iplis=ips
	else:
		mylog.error("[global function] Input type Error in ipipCheckGeo().")
		return 0
	fpath=get_ipipGeo_path()
	realpath = os.path.split(__file__)[0] + os.path.sep +".."+os.path.sep+ fpath
	#print realpath
	dbs = ipdb.City(realpath)
	redic={}
	for ip in iplis:
		if(type(ip) is not unicode):
			ip2=ip.decode()
		else:
			ip2=ip
		try:
			# encode，ipip查询仅接受unicode编码
			tmp=dbs.find(ip2, "CN")
			# newtmp=[]
			# for ii in tmp:
			# 	newtmp.append(ii.encode("utf-8"))
			redic[ip]=tmp
		except Exception,e:
			mylog.error("[global function] Check IP by ipdb errors:{0}".format(e))
	return redic



