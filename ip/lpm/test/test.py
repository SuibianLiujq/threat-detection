#!/usr/bin/python
import random
import re
import os

def generateRules():
    rules = []
    rangeset = set() # for range, any *

    for i in range(1000):
        level1 = random.randint(1, 255)
        if ("%d") % (level1) in rangeset:
            continue

        level2 = random.randint(1, 500)
        if ("%d.%d") % (level1, level2) in rangeset:
            continue
        if level2 > 255:
            rules.append(("%d.*.*.*\n") % (level1))
            rangeset.add(("%d") % (level1))
            continue

        level3 = random.randint(1, 500)
        if ("%d.%d.%d") % (level2, level2, level3) in rangeset:
            continue
        if level3 > 255:
            rules.append(("%d.%d.*.*\n") % (level1, level2))
            rangeset.add(("%d.%d") % (level1, level2))
            rangeset.add(("%d") % (level1))
            continue


        level4 = random.randint(1, 500)
        if level4 > 255:
            rules.append(("%d.%d.%d.*\n") % (level1, level2, level3))
            rangeset.add(("%d.%d.%d") % (level1, level2, level3))
            rangeset.add(("%d.%d") % (level1, level2))
            rangeset.add(("%d") % (level1))
            continue


        rules.append(("%d.%d.%d.%d\n") % (level1, level2, level3, level4))
        rangeset.add(("%d.%d.%d") % (level1, level2, level3))
        rangeset.add(("%d.%d") % (level1, level2))
        rangeset.add(("%d") % (level1))

    #print rangeset
    fp = open("configfile", "w")
    fp.writelines(rules)
    fp.close()
    return rules


def generateIPs():
    ips = []
    for i in range(10000):
        level1 = random.randint(1, 255)
        level2 = random.randint(1, 255)
        level3 = random.randint(1, 255)
        level4 = random.randint(1, 255)

        ips.append(("%d.%d.%d.%d\n") % (level1, level2, level3, level4))

    fp = open("ipfile", "w")
    fp.writelines(ips)
    fp.close()
    return ips

def make():
    tmp = os.popen("make").readlines()
    e = re.compile(r"[eE]rror")
    out = "\n".join(tmp)
    if e.match(out):
        print out
        exit()

def test(rules, ips):
    tmp = os.popen("./test configfile ipfile").readlines()
    fp = open("result", "wb");
    fp.writelines(tmp);
    fp.close()
    errors = []
    checkok = 0
    del tmp[0]
    for line in tmp:
        checkok = 0
        line.rstrip()
        two = line.split()
        ip = two[0]
        res = two[1]
        if len(two) == 4:
            ruleID = two[2]
            ag = two[3]

        for rule in rules:
            orgrule = rule
            rule = rule.rstrip()
            lis = rule.split(".")
            newlis = []
            for i in range(4):
                if i < 4:
                    if lis[i] == "*":
                        newlis[len(newlis) - 1] = "\.."
                        newlis.append("*")
                        break
                    else:
                        newlis.append(lis[i])
                        newlis.append("\.")

            rule = "".join(newlis)
            p = re.compile("%s" % rule)
            if p.match(ip):
                if res == "matcheed" and int(ruleID) == rules.index(orgrule) and (int(ruleID) % 2) == int(ag):
                    checkok = 1
                    break
                elif res == "unmatched":
                    errors.append((ip, rule, res))
        if checkok:
            continue
        if res != "unmatched":
            errors.append((ip, res))

    if errors:
        for error in errors:
            print "find error %s" % " ".join(error)
    else:
        print "test ok!"

if  __name__ == '__main__':
    make()
    rules = generateRules()
    ips = generateIPs()
    test(rules, ips)

