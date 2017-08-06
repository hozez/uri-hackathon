import ipaddress
import nltk
import re
import spacy
import spacy.symbols


nlp = spacy.load('en')


def get_verb_ancestors(
    token,
):
    ancestors = []
    ancestors = traverse_verb_ancestors(
        token,
        ancestors,
    )

    return ancestors


def traverse_verb_ancestors(
    token,
    ancestors,
):
    if token.head == token or token is None:
        return ancestors

    if token.head.pos_ == 'VERB':
        ancestors.append(token.head)

    return traverse_verb_ancestors(
        token.head,
        ancestors,
    )

def is_verb_negated(
    token,
):
    for child in token.children:
        if child.dep_ == 'neg' and child.pos_ == 'ADV':
            return True

    return False

def is_valid_candidate(
    np,
):
    allowed_deps = [
        'dobj',
        'compound',
        'pobj',
        'oprd',
        'nummod',
        'appos',
        'nsubjpass',
        'acl',
    ]

    ioc_related_verbs = [
        'communicate',
        'download',
        'install',
        'write',
        'read',
        'wipe',
        'call',
        'use',
    ]

    whiltelisted_verbs = [
        'patch',
        'release',
    ]

    allowed_dependency = np.dep_ in allowed_deps
    if not allowed_dependency:
        return False

    verb_ancestors = get_verb_ancestors(np)

    has_whitelisted_ancestor_verbs = False
    has_ioc_related_ancestor_verbs = False
    is_any_verb_negated = False
    for verb_ancestor in verb_ancestors:
        is_whitelisted_verb = verb_ancestor.lemma_ in whiltelisted_verbs
        if is_whitelisted_verb:
            has_whitelisted_ancestor_verbs = True

        # is_ioc_related_verb = verb_ancestor.lemma_ in ioc_related_verbs
        # if is_ioc_related_verb:
        #     has_ioc_related_ancestor_verbs = True

        is_any_verb_negated = is_verb_negated(verb_ancestor)

    if not allowed_dependency or has_whitelisted_ancestor_verbs:
        return False

    if allowed_dependency and not is_any_verb_negated:
        return True

    return False

def cleanText(text):
    clean = text

    mapping = ['(', ')', '“', '”', '"', ',']
    for value in mapping:
        clean = clean.replace(value, '')

    return clean

def get_context_terms(ioc_candidate):
    context_terms = {}

    text = cleanText(ioc_candidate)

    # TODO url
    # file extensions
    # [dot] instead of . in url
    # hxxp instead of http
    regexes = {
        'hash-md5'      : r'^([a-fA-F\d]{32})$',
        'hash-sha1'     : r'^([a-fA-F\d]{40})$',
        'hash-sha256'   : r'^([a-fA-F\d]{64})$',
        'ip'            : r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        'filename'      : r'\\?[\w_-]+(\.(exe|zip|dll|dat|bin|sys)+)+',
        'domain'        : r'^(:?[a-z0-9](:?[a-z0-9-]{,61}[a-z0-9])?)(:?\.[a-z0-9](:?[a-z0-9-]{0,61}[a-z0-9])?)*(:?\.[a-z][a-z0-9-]{0,61}[a-z0-9])$',
        'registry key'  : r'^(HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_CURRENT_CONFIG|HKEY_USERS|HKEY_LOCAL_MACHINE|HKCR|HKCC|HKCU|HKU|HKLM)\\.+$',
        'url'           : r'^(?:(?P<protocol>http|https|hxxp|hxxps|ftp)://)?(?:((:?[a-z0-9](:?[a-z0-9-]{,61}[a-z0-9])?)(:?\.[a-z0-9](:?[a-z0-9-]{0,61}[a-z0-9])?)*(:?\.[a-z][a-z0-9-]{0,61}[a-z0-9]))|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?P<port>:\d+)?(?P<uri>/.*)?$'
    }

    for word in text.split():
        for iocType, regex in regexes.items():
            matches = re.findall(regex, word)
            if matches:
                context_terms[word] = iocType

    return context_terms

def normalize_ioc_candidate(
    ioc_candidate,
):
    special_chars = '''-|@#$()"'''
    no_special_chars_string = ''

    for char in ioc_candidate:
        if char not in special_chars:
            no_special_chars_string += char

    no_special_chars_string = re.sub(
        pattern='\s+',
        repl=' ',
        string=no_special_chars_string,
    )

    return no_special_chars_string

def get_valid_iocs(text):
    valid_iocs = []
    ioc_candidates = nltk.sent_tokenize(text)

    for ioc_candidate in ioc_candidates:
        ioc_candidate = normalize_ioc_candidate(ioc_candidate)
        context_terms = get_context_terms(ioc_candidate)
        if not context_terms:
            continue

        analyzed_candidate = nlp(ioc_candidate)

        for token in analyzed_candidate:
            for key in context_terms.keys():
                if str(token) in key:
                    if is_valid_candidate(token):
                        if not is_whitelisted(token):
                            valid_iocs.append(str(token))

    return valid_iocs


def get_ioc_candidates():
    with open("/home/uri/Desktop/hackathon/uri-hackathon/ioc_candidates.txt", 'r') as f:
        ioc_candidates = f.readlines()

        # return ioc_candidates
        return [
            # r'''The specimen initially sent TCP SYN requests to ip address 60.10.179.100.''',
            # r'''The malware then writes the R resource data to the file C:\WINDOWS\tasksche.exe''',
            # r'''The malware executes C:\WINDOWS\tasksche.exe /i with the CreateProcess API.''',
            # r'''The malware then attempts to move C:\WINDOWS\tasksche.exe to C:\WINDOWS\qeriuwjhrf, replacing the original file if it exists.''',
            r'''The decrypted data is saved as a DLL (MD5: f351e1fcca0c4ea05fc44d15a17f8b36)''',
            r'''The file r.wnry are extracted from the XIA resource (3e0020fc529b1c2a061016dd2469ba96)''',
            # r'''The most obvious indication of malware infection was the addition of a file named “serivces.exe” in “C:\Windows\System32”''',
            # r'''The initial payload delivered through the binary named mssecsvc.exe''',
            # r'''if the malware can connect to http://iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com''',
            # r'''This bootstrap DLL reads the main WannaCrypt payload from the resource section and writes it to a file C:\WINDOWS\mssecsvc.exe''',
            # r'''This section examines a malware (hash value: aada169a1cbd822e1402991e6a9c9238) that was caught by a private honeypot''',
        ]


def is_private_ip(
    candidate,
):
    try:
        ip_parsed = ipaddress.IPv4Address(
            address=candidate,
        )
    except ValueError:
        return False
    else:
        return ip_parsed.is_private


def is_known_process_name(
    candidate,
):
    well_known_process_names = [
        'schedlgu.exe',
        'calc.exe',
    ]
    if candidate in well_known_process_names:
        return True

    return False


def is_whitelisted(
    candidate,
):
    if is_private_ip(
        candidate=candidate.text,
    ):
        return True

    if is_known_process_name(
        candidate=candidate.text,
    ):
        return True

    return False


def main():
    ioc_candidates = get_ioc_candidates()
    for ioc_candidate in ioc_candidates:
        try:
            valid_iocs = get_valid_iocs(ioc_candidate)
            print(ioc_candidate.strip())
            print(valid_iocs)
            print()
        except Exception as ex:
            print(ex)


if __name__ == '__main__':
    main()
