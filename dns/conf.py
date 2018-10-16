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
	return os.path.abspath(os.path.join(os.path.split(__file__)[0],"data/"))
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
	freq = __conf["freq"]
	
	frequency = []

	if freq["start_time"] == "now":
		freq["start_time"] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

	regex1=re.compile(r'\d+')
	regex2=re.compile(r'[a-zA-Z]+')
	period_num = regex1.findall(freq["period"])[0]
	period_scale = regex2.findall(freq["period"])[0].upper()
	if period_scale == 'S' :
		period  = datetime.timedelta(seconds = int(period_num))
	elif period_scale == 'M':
		period = datetime.timedelta(minutes = int(period_num))
	elif period_scale == 'D':
		period = datetime.timedelta(days = int(period_num))
	freq["period"] = period

	freq["offset"] = datetime.timedelta(seconds = freq["offset"])

	return freq
# print set_frequency()

#############################################################################################################################

ES_config = get_es_config()
ES_config["dns_index"] = __conf["index"]

#############################################################################################################################
	
ES_client = get_es_client()

############################################################################################################################

syslogger = get_syslog_config()

def get_others_config():
	return __conf["others"]
# print get_others_config()



