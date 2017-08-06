import re

def cleanText(text):
    clean = text

    mapping = ['(', ')', '“', '”', '"', ',']
    for value in mapping:
        clean = clean.replace(value, '')

    return clean

text = 'we found (192.168.2.2) a hash 900e3f2dd4efc9892793222d7a1cee4a and test-sdsd.exe thing.zip t.sh  malware.txt www.google.com 418c1f073782a1c855890971ff18794f7a298f6d and another one AC905DD4AB2038E5F7EABEAE792AC41B and also 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069 and'

text = """
The decrypted data is saved as a DLL (MD5: f351e1fcca0c4ea05fc44d15a17f8b36)
"""

text = cleanText(text)

# TODO url
# file extensions
# [dot] instead of . in url
# hxxp instead of http
regexes = {
    'hash-md5'      : r'^([a-fA-F\d]{32})$',
    'hash-sha1'     : r'^([a-fA-F\d]{40})$',
    'hash-sha256'   : r'^([a-fA-F\d]{64})$',
    'ip'            : r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
    'domain'        : r'^(\w\.|\w[A-Za-z0-9-]{0,61}\w\.){1,3}[A-Za-z]{2,6}$',
    'filename'      : r'^[\w-]+\.exe|zip$',
    'registry key'  : r'^(HKEY_CURRENT_USER|HKCU|HKLM)\\.+$'
}

print 'looking for IoC in the text: "%s"\n' % (text)
for word in text.split():
    # print word
    for iocType, regex in regexes.iteritems():
        matches = re.findall(regex, word)
        if matches:
            # print matches
            print '%s is a %s' % (word, iocType)
