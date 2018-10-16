import re,datetime,platform,os,json
import logging,logging.handlers
from cloghandler import ConcurrentRotatingFileHandler

__conf_dir = os.path.join(os.path.split(__file__)[0],"../cfg/conf_dns.json")
with open(__conf_dir,'r') as f:
	__conf = json.loads(f.read())

##############################################################################################################################

def platform_detection():
    pattern_platform = re.compile("^[^-]*")
    return pattern_platform.findall(platform.platform())[0]
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

def set_logger():
	log_level = __conf["log"]["level"].upper()
	log_path = os.path.abspath(os.path.join(os.path.split(__file__)[0],"../logs/threat-detection"))
	log_size = 4*1024*1024

	log = logging.getLogger("mal_dns")

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

def get_es_config():
	#ES configuration
	return __conf["es_server"]

# print get_es_config()

#############################################################################################################################

def get_es_client():
	#ES configuration
	es_client = __conf["es_client"]
	
	if es_client["enable"]:
		return es_client
	else:
		return False
	
# print get_es_client()

############################################################################################################################

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

def get_others_config():
	return __conf["others"]
# print get_others_config()



