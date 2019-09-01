#!/usr/bin/python
# -*- coding: utf-8 -*-
import random
import string
import socket
import re
import sys
import itertools
class Domain_whois():
    hostdict = {'com': 'whois.internic.net',
                'me': 'whois.nic.me', 'cn': 'whois.cnnic.cn',
                'cc': 'whois.nic.cc', 'net': 'whois.internic.net'}
    fword = {'com':'No match','me':'NOT FOUND','cc':'No match','net':'No match','cn':'No matching record'}
    #获取whois
    def get_whois(self,name,suffix):
        domain = name+'.'+suffix
        host = self.hostdict[suffix]
        s = socket.socket()
        s.connect((host,43))
        s.send(domain.encode('idna') + b"\r\n")
        v = s.recv(4096).decode()
        return v

    #提取asd返回的相关信息的字典
    def extract(self,name,suffix):
        info = self.get_whois(name,suffix)
        whois = {}
        whois['domain_name'] = re.search('Domain Name:(.*)',info).group(1).lower()
        whois['creation_date'] = re.search('Creation Date:(.*)|Registration Time:(.*)',info).group(1).lower()
        whois['expiration_date'] = re.search('Expiration Date:(.*)|Registry Expiry Date:(.*)|Registration Time:(.*)',info)
        return whois

    #判断是否可注册
    def ornot(self,name,suffix):
        info = self.get_whois(name,suffix)
        num = info.find(self.fword[suffix])
        domain = name+'.'+suffix
        if num>=0:print('%s可注册'%domain)
        else:print('%s已被注册'%domain)
        return num

def Random_char(len):
    Str_list=[]
    if len<=0:
        return Str_list
    if len==1:
        return list(string.ascii_lowercase)
    else:
        Str = Random_char(len-1)
        for ch in string.ascii_lowercase:
            Str_list.extend([ch+i for i in Str])
        return Str_list

def Pop_str(Str_list):
    if Str_list:
        strlist=random.choice(Str_list)
        Str_list.remove(strlist)
        return strlist
    else:
        pass

def Str_sort(Str_list):
    Str_listed=[]
    if Str_list:
        liststr=list(itertools.permutations(Str_list,len(Str_list)))
        for i in liststr:
            Str_listed.append(''.join(i))
    return Str_listed

def Write_files(domain_request,domain):
    if domain_request != -1:
        with open('oklist.txt','a+') as ok:
            ok.write(domain+'\n')

def domain(namepart='',suffix="com",domainlen=4):
    active = True
    if domainlen-len(namepart)<0:
        sys.exit()
    else:
        name_list=Random_char(domainlen-len(namepart))
    cow=Domain_whois()
    while active:
        if name_list:
            salt=Pop_str(name_list)
            if namepart:
                salt_list=(list(salt))
                salt_list.append(namepart)
                salt_listed=Str_sort(salt_list)
                for i in salt_listed:
                    domain_request=cow.ornot(i,suffix)
                    Write_files(domain_request,i+'.'+suffix)
            else:
                domain_request=cow.ornot(salt,suffix)
                Write_files(domain_request,salt+'.'+suffix)
        else:
            domain_request=cow.ornot(namepart,suffix)
            Write_files(domain_request,namepart+'.'+suffix)
            active=False

if __name__ == '__main__':
   domainstr = raw_input('输入域名关键字: ')
   domainlen = input('输入域名长度：')
#    domainmax = input('输入域名个数: ')
   domain(domainstr,"com",domainlen)
    #  domain(sys.argv[1],"com",int(sys.argv[2]))
