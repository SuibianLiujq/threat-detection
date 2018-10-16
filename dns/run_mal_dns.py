#!/usr/bin/python

import os
import time
import datetime
from conf import set_data_path,set_frequency,log,get_others_config
import TrieSearch,merge_blacklist

data_path = set_data_path()
frequency = set_frequency()
others    = get_others_config()

def store_run(storeDate):
    try:
        log.info("Download starting.")

        merge_blacklist.main(storeDate)

        log.info("Download completed.")

    except Exception, e:
        log.error("Download failed.\n{0}".format(e))

def run():
    entertime = frequency["start_time"]
    delta = frequency["period"]
    offset = frequency["offset"]

    startTime = datetime.datetime.strptime(entertime, '%Y-%m-%d %H:%M:%S')
    #begin= '2017-05-24 23:59:57'
    #beginTime = datetime.datetime.strptime(begin, '%Y-%m-%d %H:%M:%S')
    #print startTime
    log.info("Starting theat DNS checking.")
    if others["offline"]:
        log.info("Enable offline , use default intelligence.")
    count = 0
    while True:
        time.sleep(count)
        log.info("The next start time :{0}".format(startTime))
        if datetime.datetime.now() < startTime:
            minus_time = startTime - datetime.datetime.now()
            sleep_time = minus_time.days*86400+minus_time.seconds
            # print sleep_time
            time.sleep(sleep_time)

        storeDate = datetime.datetime.now().strftime('%Y-%m-%d')
        blacklist_dir = os.path.join(data_path,'source'+'-'+storeDate+".json")
        # print blacklist_dir
        blacklist_Trie_dir = os.path.join(data_path,'trie'+'-'+storeDate+".json")
        # print blacklist_Trie_dir

        if  (not others["offline"]) and not ((os.path.exists(blacklist_dir) and os.path.exists(blacklist_Trie_dir))):
            store_run(storeDate)

        try:
            log.info("Checking the DNS.")
            # execute the command
            gte = (startTime-delta-offset).strftime('%Y-%m-%d %H:%M:%S')
            lte = (startTime-offset).strftime('%Y-%m-%d %H:%M:%S')

            if time.daylight == 0:
                time_zone = "%+03d:%02d" % (-(time.timezone/3600),time.timezone%3600/3600.0*60)
            else:
                time_zone = "%+03d:%02d" % (-(time.altzone/3600),time.altzone%3600/3600.0*60)

            timestamp = (startTime).strftime('%Y-%m-%dT%H:%M:%S.%f')+time_zone

            TrieSearch.main(gte,lte,timestamp,time_zone)

            # command = r'python TrieSearch.py "%s" "%s" "%s"' %(gte,lte,timestamp)
            # status = os.system(command)
            log.info("Checking completed.")
            # print("Command status = %s."%status)
            startTime = startTime+delta
            count = 0
        except Exception, e:
            log.error("Checking failed.\n{0}".format(e))
            count += 1

if __name__=="__main__":
    run()
