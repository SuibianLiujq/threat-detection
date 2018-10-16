#!/usr/bin env python

__version__ = "0.1"

from ctypes import *
import os

# linux :
#cdll.LoadLibrary(os.getcwd()+'/lpm/lpm.so')
#windows
print os.getcwd()
# lib_lpm = cdll.LoadLibrary(os.getcwd()+'\lpm\lpm.so')
lib_lpm = cdll.LoadLibrary(os.getcwd()+os.path.sep+'lpm'+os.path.sep+'lpm.so')

def init():
    lib_lpm.lpm_init_rule()
    return 0

def insert_rule(ip_string):
    ret = lib_lpm.lpm_insert_rule(ip_string)
    return ret

def search_ip(ip_int):
    ret = lib_lpm.lpm_search_rule(ip_int)
    return ret




