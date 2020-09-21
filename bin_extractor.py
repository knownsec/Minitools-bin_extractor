#!/usr/bin/env python
#coding:utf-8
"""
  Author:   --<>
  Purpose: 
  Created: 09/12/17
"""

import re
import optparse
import requests
from multiprocessing.dummy import Pool as ThreadPool


class Result:
    """"""
    #----------------------------------------------------------------------
    def __init__(self, domain, port, scheme='http', timeout=5):
        self.urls = set()
        self.keys = set()
        self.ips = set()
        self.paths = set()
        self.ok_urls = []
        self.domain = domain
        self.port = port
        self.scheme = scheme

    
class TextMatcher(object):
    __slots__ = ('plain_array', 'regex_array', 'search_text', 'findall_text')
    def __init__(self):
        self.plain_array = []
        self.regex_array = []
        
    def search_text(self, text, index=0):
        if not text:
            return False
        # search plain texts first
        for keyword in self.plain_array:
            if keyword in text:
                return keyword
            
        # search regexes
        for regex in self.regex_array:
            match = re.search(regex, text)
            if match:
                return match.group(index) if index > 0 else match.group(0)
            
        return False
    
    def findall_text(self, text):
        retval = []
        if not text:
            return retval
        
        for regex in self.regex_array:
            data = re.findall(regex, text)
            retval.extend(data)
            
        retval = list(set(retval))
        
        return retval

def test_for_server_path_unix(value):
    matches = TextMatcher()
    matches.regex_array = [
        r"""[\s\t:><|\(\)\[\}](\/(var|www|usr|Users|user|tmp|etc|home|mnt|mount|root|proc)\/[\w\/\.]*(\.\w+)?)"""
    ]
    matched_text = matches.search_text(value, index=1)
    if matched_text:
        dirs = matched_text.split('/')
        if dirs and len(dirs) > 3:
            return matched_text
    return None

def test_for_http_urls(value):
    protocols = '((https?|s?ftp|irc[6s]?|git|afp|telnet|smb):\/\/)'
    userInfo = '([a-z0-9]\w*(\:[\S]+)?\@)?'
    domain = '([A-Za-z0-9-]+\.)+[A-Za-z]{2,}'
    port = '(:\d{1,5})?'
    ip = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    address = '[.\/=\?%\-&_~`@[\]\':+!]*([^\"\"])*?'
    domain_type = [protocols, userInfo, domain, port, address]
    ip_type = [protocols, userInfo, ip, port, address]
    
    regex1 = '(^'+ ''.join(domain_type) + '$)'
    regex2 = '(^'+ ''.join(ip_type) + '$)'
    
    matches = TextMatcher()
    matches.regex_array = [regex1, regex2]
    matched_text = matches.search_text(value, index=1)
    return matched_text if matched_text else None

def test_for_emails(value):
    matches = TextMatcher()
    matches.regex_array = [
        r"""[a-z0-9!#?+=?^_~-]+(?:\.[a-z0-9!#?+=?^_~-]+)*?@(?:[a-z0-9](?:[a-z0-9-]*?[a-z0-9])?\.)+(?:[A-Z]{2}|asia|com|cn|org|net|gov|edu|mil|biz|info|mobi|name|aero|jobs|museum|travel|tv|us|cc|it|me|hk|jp|kr|tw|ru|la|sh)\b"""
    ]

    emails = matches.findall_text(value)
    return emails

def test_for_keys(value):
    ret = set()
    matches = TextMatcher()
    matches.regex_array = [
        "(?ms)(^-----BEGIN RSA PUBLIC KEY-----.*?-----END RSA PUBLIC KEY-----$)",
        "(?ms)(^-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----$)",
        "(?ms)(^-----BEGIN DSA PRIVATE KEY-----.*?-----END DSA PRIVATE KEY-----$)",
        "(?ms)(^-----BEGIN EC PRIVATE KEY-----.*?-----END EC PRIVATE KEY-----$)",
        "(?ms)(^-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----$)",
        "(?ms)(^-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----$)",
    ]
    keys = matches.findall_text(value)
    for key in keys:
        ret.add(key)
    return ret

def test_for_ips(value):
    matches = TextMatcher()
    matches.regex_array = [
        r"""^([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\.([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\.([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\.([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])$"""
    ]
    matched_text = matches.search_text(value)
    if matched_text in ['0.0.0.0', '127.0.0.1']:
        matched_text = None
    return matched_text if matched_text else None

def test_for_url_path(value):
    matches = TextMatcher()
    matches.regex_array = [
        r"""(\/[\w\/\.]*(\.\w+)?)"""
    ]
    ban_chars = ['//','../']
    matched_text = matches.search_text(value)
    for ban_char in ban_chars:
        if matched_text and ban_char in matched_text:
            matched_text = None
    return matched_text if matched_text else None


def verify_result(result):
    def query(url):
        try:
            requests.packages.urllib3.disable_warnings()
            resp = requests.get(url, verify=False)
            if resp.status_code != 404:
                return url
        except:
            pass
        return None
    
    urls = ['%s://%s:%s%s' %(result.scheme, result.domain, result.port, i) for i in result.paths] 
    tp = ThreadPool(20)
    url_list = tp.map(query, urls)
    ok_urls = filter(lambda x:x is not None, url_list)
    result.ok_urls = ok_urls
    tp.close()
    tp.join()
    return ok_urls
    

def print_result(result):
    print '[+] Results\n'
    print "#### URLs: (%d) ####" %len(result.urls)
    for i in result.urls:
        print "%s" % i
        
    print "\n#### IPs: (%d) ####" %len(result.ips)
    for i in result.ips:
        print "%s" % i    
        
    print "\n#### Paths with hostname: (%d) ####" %len(result.ok_urls)
    for i in result.ok_urls:
        print "%s" % i
        
    print "\n\n###### KEYs: (%d) ####" %len(result.keys)
    for i in result.keys:
        print "%s\n" % i
    

def main():
    parser = optparse.OptionParser(version='0.1')
    parser.add_option("-f", "--file", dest="filename", help="strings dump file")
    parser.add_option("-s", "--scheme", dest="scheme", default='http', help="url scheme http or https, default(http)")
    parser.add_option("-d", "--domain", dest="domain", help="url domain")
    parser.add_option("-p", "--port", dest="port", help="url port")
    parser.add_option("-t", "--timeout", dest="timeout", help="url verify timeout")
    parser.add_option("-v", "--verify", dest="verify", action="store_true", help="url path verify")
    
    options, _ = parser.parse_args()
    if not options.filename:
        parser.print_help()
    else:
        result = Result(options.domain, options.port, options.scheme, options.timeout)
        try:
            print '[*] Searching senstive data from file "%s" ...' % options.filename
            file_object = open(options.filename,'rU')
            for line in file_object:
                url = test_for_http_urls(line)
                if url:
                    result.urls.add(url)
                ip = test_for_ips(line)
                if ip:
                    result.ips.add(ip)
                path = test_for_url_path(line)
                if path:
                    result.paths.add(path)
        finally:
            file_object.close()
        
        try:
            file_object = open(options.filename)
            file_context = file_object.read()
            keys = test_for_keys(file_context)
            if keys:
                result.keys = keys
        finally:
            file_object.close()
            
        if options.verify:
            print '[*] Verify %d url paths ...' % len(result.paths)
            verify_result(result)
        print_result(result)

if __name__ == '__main__':
    # strings * > /tmp/data.txt
    # python bin_extractor.py -f /tmp/data.txt -s https -d 10.10.0.106 -p 10443 -v
    main()