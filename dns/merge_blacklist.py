# -*- coding: utf-8 -*-
import os,sys
from blacklist_tools import *
from conf import set_data_path,get_moudle_name,log

data_path = set_data_path()
moudle_name = get_moudle_name()

sys.dont_write_bytecode = True

# 存储原始数据
def get_blacklist_module():
    parse_blacklist = moudle_name
    for file_name in parse_blacklist:
        module = __import__('get_blacklist.{0}'.format(file_name),fromlist=True)
        log.debug('Downloading {0}.'.format(file_name))
        try:
            module.main()
            log.debug('Download {0} completed.'.format(file_name))
        except Exception as e:
            log.error('Download {0} failed.'.format(file_name))
        

def merge_blacklist(date,name):
    parse_blacklist = moudle_name
    flag = 0
    merge_result = {}
    for file_name in parse_blacklist:
        if os.path.exists(file_name + '.json'):
            result = load_dict(file_name + '.json')
            if not result:
                log.warn("[mal_dns] {0} no data!".format(file_name))
                delete_file()
                return False
        else:
            log.warn("[mal_dns] {0} not found!".format(file_name))
            delete_file()
            return False
        # print len(result)
        if flag ==0:
            merge_result = result
            flag = 1
        else:
            merge_result = update_dict(result,merge_result)
            
    saveAsJSON(date,merge_result,data_path,name)
    saveAsJSON("default",merge_result,data_path,name)

    delete_file()

def delete_file():
    for file_name in moudle_name:
        if os.path.exists(file_name+'.json'):
            os.remove(file_name+'.json')

#建Trie树

def store_trie(date, name):
    path = os.path.join(data_path , 'source' + "-" +date + '.json')
    if not os.path.exists(path):
        log.warn("[mal_dns] {0} not found!".format(path))
        return False
    result = load_dict(path)
    # print result
    trie = create_Trie([x.split('.') for x in result.keys()])
    saveAsJSON(date,trie,data_path,name)
    saveAsJSON("default",trie,data_path,name)

def main(storeDate):
    get_blacklist_module()
    merge_blacklist(storeDate,'source')
    store_trie(storeDate,'trie')



