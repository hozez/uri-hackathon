import ipaddress
import tldextract
import nltk
import re
import csv
import spacy
import spacy.symbols
import collections

nlp = spacy.load('en')
tld_extractor = tldextract.TLDExtract(
    include_psl_private_domains=True,
)

trusted_organizatons = [
    'microsoft',
    'vmware',
    'antivirus',
    'anti-virus',
    'anti virus',
    'linux',
    'google',
    'mcafee',
    'symantec',
]

def load_alexa_top_domains():
    with open('top-1m.csv') as csvfile:
        sites_reader = csv.reader(csvfile)
        for row in sites_reader:
            yield row[1]


top_domains = list(load_alexa_top_domains())
valid_domain_regex = re.compile(
    pattern=r'^(:?[a-z0-9](:?[a-z0-9-]{,61}[a-z0-9])?)(:?\.[a-z0-9](:?[a-z0-9-]{0,61}[a-z0-9])?)*(:?\.[a-z][a-z0-9-]{0,61}[a-z0-9])$',
    flags=re.IGNORECASE,
)

def get_ancestors(
    token,
    desired_part_of_speech,
):
    ancestors = []
    ancestors = traverse_ancestors(
        token,
        ancestors,
        desired_part_of_speech,
    )

    return ancestors


def traverse_ancestors(
    token,
    ancestors,
    desired_part_of_speech,
):
    if token.head == token or token is None:
        return ancestors

    if desired_part_of_speech:
        if token.head.pos_ == desired_part_of_speech:
            ancestors.append(token.head)
    else:
        ancestors.append(token.head)

    return traverse_ancestors(
        token.head,
        ancestors,
        desired_part_of_speech,
    )


def is_verb_negated(
    token,
):
    for child in token.children:
        if child.dep_ == 'neg' and child.pos_ == 'ADV':
            return True

    return False


def get_is_verb_applied_by_trusted_organization(
    token,
):

    # ancestors = get_ancestors(token, 'NOUN')
    # ancestors += get_ancestors(token, 'PROPN')
    # for ancestor in ancestors:
    #     if str(ancestor).lower in trusted_organizatons:
    #         return True
    for child in token.children:
        if child.pos_ == 'NOUN' or child.pos_ == 'PROPN':
            if str(child).lower() in trusted_organizatons:
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
        'conj',
        'punct',
    ]

    ioc_related_verbs = [
        'communicate',
        'download',
        'install',
        'connect'
        'write',
        'read',
        'wipe',
        'call',
        'use',
    ]

    whiltelisted_verbs = [
        'patch',
        'release',
        'protect',
        'mitigate',
        'cures',
    ]

    allowed_dependency = np.dep_ in allowed_deps
    if not allowed_dependency:
        return False

    verb_ancestors = get_ancestors(np, 'VERB')

    has_whitelisted_ancestor_verbs = False
    is_any_verb_negated = False
    for verb_ancestor in verb_ancestors:
        is_verb_applied_by_trusted_organization = get_is_verb_applied_by_trusted_organization(verb_ancestor)
        is_whitelisted_verb = verb_ancestor.lemma_ in whiltelisted_verbs or is_verb_applied_by_trusted_organization
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

def determined_match_correct(
    word,
    ioc_type,
):
    if ioc_type == 'ip':
        try:
            ipaddress.IPv4Address(word)
        except ValueError:
            return False
    elif ioc_type == 'domain':
        if not tld_extractor(
            url=word,
        ).suffix:
            return False

    return True


def get_context_terms(ioc_candidate):
    context_terms = {}

    text = cleanText(ioc_candidate)

    regexes = collections.OrderedDict()
    regexes['hash-md5']     = r'^([a-fA-F\d]{32})$'
    regexes['hash-sha1']    = r'^([a-fA-F\d]{40})$'
    regexes['hash-sha256']  = r'^([a-fA-F\d]{64})$'
    regexes['ip']           = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    regexes['domain']       = r'^((?:[a-z0-9](?:[a-z0-9-]{,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*(?:\.[a-z][a-z0-9-]{0,61}[a-z0-9]))$'
    regexes['url']          = r'^((?:(?:hxxp|hxxps|http|https|ftp)://)?(?:((?:[a-z0-9](?:[a-z0-9-]{,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*(?:\.[a-z][a-z0-9-]{0,61}[a-z0-9]))|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\d+)?(?:/.*)?)$'
    regexes['filename']     = r'((?:[\w_:\\\.-])+(?:\..{0,5}){1}$)'
    regexes['registry key'] = r'^((?:HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_CURRENT_CONFIG|HKEY_USERS|HKEY_LOCAL_MACHINE|HKCR|HKCC|HKCU|HKU|HKLM)(?:\\{1,2}[\w]|[\w])+)$'

    for word in text.split():
        for ioc_type, regex in regexes.items():
            matches = re.findall(regex, word)
            if matches:
                if determined_match_correct(word, ioc_type):
                    if isinstance(matches[0], tuple):
                        word_to_match = matches[0][0]
                    else:
                        word_to_match = matches[0]
                        
                    context_terms[word_to_match] = ioc_type

                    break

    return context_terms


def normalize_ioc_candidate(
    ioc_candidate,
):
    special_chars = '''”“-|@#$()"'''
    no_special_chars_string = ''

    for char in ioc_candidate:
        if char not in special_chars:
            no_special_chars_string += char

    no_special_chars_string = re.sub(
        pattern='\s+',
        repl=' ',
        string=no_special_chars_string,
    )

    return no_special_chars_string.lower().strip().rstrip('.')

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
            if str(token) in context_terms.keys():
                if is_valid_candidate(token):
                    if not is_whitelisted(token):
                        valid_iocs.append(str(token))

    return valid_iocs


def get_ioc_candidates():
    # return [
    #     r'''The specimen initially sent TCP SYN requests to ip address 60.10.179.100.''',
    #     r'''The specimen initially sent TCP SYN requests to ip address 192.168.0.200.''',
    #     r'''The malware then writes the R resource data to the file C:\WINDOWS\tasksche.exe''',
    #     r'''The malware executes C:\WINDOWS\tasksche.exe /i with the CreateProcess API.''',
    #     r'''The malware then attempts to move C:\WINDOWS\tasksche.exe to C:\WINDOWS\qeriuwjhrf, replacing the original file if it exists.''',
    #     r'''The decrypted data is saved as a DLL (MD5: f351e1fcca0c4ea05fc44d15a17f8b36)''',
    #     r'''The file r.wnry are extracted from the XIA resource (3e0020fc529b1c2a061016dd2469ba96)''',
    #     r'''The most obvious indication of malware infection was the addition of a file named “serivces.exe” in “C:\Windows\System32”''',
    #     r'''The initial payload delivered through the binary named mssecsvc.exe''',
    #     r'''the malware communicates with http://iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com''',
    #     r'''This bootstrap DLL reads the main WannaCrypt payload from the resource section and writes it to a file C:\WINDOWS\mssecsvc.exe''',
    #     r'''This bootstrap DLL reads the main WannaCrypt payload from the resource section and writes it to a file C:\WINDOWS\mssecsvc.exe''',
    #     r'''This section examines a malware that communicates with the domain google.com''',
    #     r'''This section examines a malware that communicates with the domain thisisavirus.com''',
    # ]

    return ['''The antivirus downloads patch.exe''']


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
        'kernel32.dll',
        'rundll32.dll',
    ]
    if candidate in well_known_process_names:
        return True

    return False


def is_top_domain(
    candidate,
):
    if valid_domain_regex.match(candidate) is not None:
        if candidate in top_domains:
            return True

    return False


def is_whitelisted(
    candidate,
):
    candidate_text = candidate.text
    if is_private_ip(
        candidate=candidate_text,
    ):
        return True

    if is_known_process_name(
        candidate=candidate_text,
    ):
        return True

    if is_top_domain(
        candidate=candidate_text,
    ):
        return True

    return False


def main():
    ioc_candidates = get_ioc_candidates()
    for ioc_candidate in ioc_candidates:
        valid_iocs = get_valid_iocs(ioc_candidate)
        print(ioc_candidate.strip())
        print(valid_iocs)
        print()


if __name__ == '__main__':
    main()
