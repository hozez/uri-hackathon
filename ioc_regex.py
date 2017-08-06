import re

def cleanText(text):
    clean = text

    mapping = ['(', ')', '“', '”', '"', ',']
    for value in mapping:
        clean = clean.replace(value, '')

    return clean

text = 'we found (192.168.2.2) a hash 900e3f2dd4efc9892793222d7a1cee4a and test-sdsd.exe thing.zip t.sh  malware.txt www.google.com 418c1f073782a1c855890971ff18794f7a298f6d and another one AC905DD4AB2038E5F7EABEAE792AC41B and also 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069 and'

text = """
APPENDIX B: IOCS
Filenames
(Note: we believe many of these to be borrowed from
legitimate files)
• agent_wininet_dl.exe • amdh264enc32.bin • amdh264enc32.dll • amdhcp32.dll • amdhdl32.dll • amdmftdecoder_32.dll • amdmftvideodecoder_32.bin • amdmftvideodecoder_32.dll • amdmiracast.dll • amdocl_as32.exe • amdocl.bin • amdocl_ld32.exe • amd_opencl32.dll • amdpcom32.bin • atiadlxx.bin • atiadlxx.dll • atiapfxx.exe • atibtmon.exe • aticalcl.dll • aticaldd.dll • aticalrt.dll • aticfx32.bin • aticfx32.dll • atidemgy.bin • atidxx32.bin • atidxx32.dll • atieclxx.exe • atiesrxx.exe • atiglpxx.dll • atiicdxx.dat • atikmdag.sys • atimuixx.dll • atiodcli.exe • atiode.exe • atioglxx.bin • atisamu32.dll • atiu9pag.bin • atiuxpag.dll • ativce02.dat • ativvaxy_cik.dat
• ativvaxy_cik_nd.dat • ativvsva.dat • ativvsvl.dat • autorun.dll • autorun_com.dll • autorun_curver.dll • clinfo.exe • coinst_13.152.dll • observers.dll • ovdecode.dll • wininetp.dll 

User agent strings
• Java/1.8.0_25 • Java/1.8.0_26 • iTunes/12.0.1 (Windows; N) • Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko • Mozilla/5.0 (Windows NT 6.1; WOW64; rv:32.0) Gecko/20100101 Firefox/32.0 • Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome /34.0.1847.137 Safari/537.36

Mutexes
• Mtx
• qdfrty
• AgentMutex 
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
    'domain'        : r'^(\w\.|\w[A-Za-z0-9-]{0,61}\w\.){1,3}(?!exe|zip|dll|dat|bin|sys)[A-Za-z]{2,6}$',
    'filename'      : r'^[\w-]+\.exe|zip|dll|dat|bin|sys$',
    'registry key'  : r'^(HKEY_CURRENT_USER|HKCU|HKLM)\\.+$',
    'url'           : r'((?:[a-z][\w\-]+:(?:\/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}\/)(?:[^\s()<>]|\((?:[^\s()<>]|(?:\([^\s()<>]+\)))*\))+(?:\((?:[^\s()<>]|(?:\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?«»“”‘’]))'
}

print 'looking for IoC in the text: "%s"\n' % (text)
for word in text.split():
    # print word
    for iocType, regex in regexes.iteritems():
        matches = re.findall(regex, word)
        if matches:
            # print matches
            print '%s is a %s' % (word, iocType)
