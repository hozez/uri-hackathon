import re
import spacy
import spacy.symbols # nsubj, VERB, dobj


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
    ]

    ioc_related_verbs = [
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

        is_ioc_related_verb = verb_ancestor.lemma_ in ioc_related_verbs
        if is_ioc_related_verb:
            has_ioc_related_ancestor_verbs = True

        is_any_verb_negated = is_verb_negated(verb_ancestor)

    if not allowed_dependency or has_whitelisted_ancestor_verbs:
        return False

    if allowed_dependency and has_ioc_related_ancestor_verbs and not is_any_verb_negated:
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
        'ip'            : r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
        'domain'        : r'^(\w\.|\w[A-Za-z0-9-]{0,61}\w\.){1,3}(?!exe|zip|dll|dat|bin|sys)[A-Za-z]{2,6}$',
        'filename'      : r'^[\w-]+\.exe|zip|dll|dat|bin|sys$',
        'registry key'  : r'^(HKEY_CURRENT_USER|HKCU|HKLM)\\.+$',
        'url'           : r'((?:[a-z][\w\-]+:(?:\/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}\/)(?:[^\s()<>]|\((?:[^\s()<>]|(?:\([^\s()<>]+\)))*\))+(?:\((?:[^\s()<>]|(?:\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?«»“”‘’]))'
    }

    for word in text.split():
        for iocType, regex in regexes.items():
            matches = re.findall(regex, word)
            if matches:
                context_terms[word] = iocType

    return context_terms

def get_valid_iocs(ioc_candidate):
    valid_iocs = []
    context_terms = get_context_terms(ioc_candidate)
    if not context_terms:
        return []

    analyzed_candidate = nlp(ioc_candidate)

    for token in analyzed_candidate:
        if str(token) in context_terms.keys():
            if is_valid_candidate(token):
                valid_iocs.append(str(token))

    return valid_iocs

def get_ioc_candidates():
    with open("/home/uri/Desktop/hackathon/uri-hackathon/ioc_candidates.txt", 'r') as f:
        ioc_candidates = f.readlines()

        # return ioc_candidates
        return ['The following command line syntax can be used to install x64 bit elsa dlls from a 32 bit process: > %WINDIR%\sysnative\regsvr32.exe /s %WINDIR%\ELSA_x64.dll']

ioc_candidates = get_ioc_candidates()
for ioc_candidate in ioc_candidates:
    try:
        valid_iocs = get_valid_iocs(ioc_candidate)
        print(ioc_candidate.strip())
        print(valid_iocs)
        print()
    except Exception as ex:
        print(ex)
