import re,datetime,platform,os,json,sys
sys.path.append(os.path.join(os.path.split(__file__)[0],"../"))
from global_tools import *

__conf_dir = os.path.join(os.path.split(__file__)[0],"../cfg/conf_dns.json")
with open(__conf_dir,'r') as f:
	__conf = json.loads(f.read())

##############################################################################################################################

# print platform_detection()

#############################################################################################################################

# Set store path .
def set_data_path():
	return os.path.join(os.path.dirname(os.path.abspath(__file__)),"data")
# print set_data_path()

#############################################################################################################################        
    
# get blacklist function module
def get_moudle_name():
	return __conf["func"]
# print get_moudle_name()

#############################################################################################################################

log = set_logger()

#############################################################################################################################

def set_frequency():
	time_config = get_time_config()

	freq = {
		"start_time": time_config["startTime"],
		"period": time_config["interval"],
		"offset": time_config["offset"]
	}

	return freq
# print set_frequency()

#############################################################################################################################

ES_config = get_es_config()
ES_config["dns_index"] = __conf["index"]["dns"]
ES_config["tcp_index"] = __conf["index"]["tcp"]

#############################################################################################################################
	
ES_client = get_es_client()

#############################################################################################################################

syslogger = get_syslog_config()

def get_others_config():
	return __conf["others"]
# print get_others_config()

#############################################################################################################################
def get_dept_info(sip):
	localIPSegment = get_local_ipsegment()
	return get_sip_dpInfo(sip,localIPSegment)

def get_ipip_geo(dip):
	ipipGeo = ipipCheckGeo(dip.encode("utf-8"))
	return ipipGeo[dip]

def is_offline():
	try:
		return isOffline()
	except Exception as e:
		log.error(e)
		raise e
