#! /usr/bin/python
# _*_ Coding:UTF-8 _*_
# author: songh
'''
update each blacklist , each them in different file.
step1 : create a daily dir
step2 : save or update each blacklist
'''
import sys
sys.path.append('..')
import os
import parser_config
import time
import blacklist_tools
from global_tools import set_logger

#save data
def update_blacklist_module(flgnum):
    mylog=set_logger()
    parser_blacklist=parser_config.get_func()
    for filename in parser_blacklist.keys():
        times=int(parser_blacklist[filename])
        # check the update frequency
        #mylog.info("check frequency.")
        if(flgnum%times==0):
            # command='python %s'%fpath
            try:
                df = __import__('get_blacklist.{}'.format(filename), fromlist=True)
                #mylog.info("start update {} ".format(filename))
                df.main()
                # status=os.system(command)
                # print status
            except Exception,e:
                # print e
                mylog.error(e)

def main(tday,flgnum):
    mylog=set_logger()
    #print("Starting update command."), time.ctime()
    mylog.info("{0}[mal_ip] Starting update command.{1}".format("-"*15,"-"*15))
    # dirpath=".\data\\%s\\"%tday
    dirpath=parser_config.get_store_path()[1]+str(tday)+os.path.sep
    if(not os.path.exists(dirpath)):
        os.mkdir(dirpath)
    update_blacklist_module(flgnum)
    # print("update finish."), time.ctime()
    mylog.info("{0}[mal_ip] update finish.{1}".format("-"*15,"-"*15))