import spacy
import spacy.symbols # nsubj, VERB, dobj

nlp = spacy.load('en')
doc = nlp(u'The malware writes the file wannacry.exe to the server')

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


def is_valid_candidate(
    np,
):
    allowed_deps = [
        'dobj',
        'compound',
    ]

    ioc_related_verbs = [
        'download',
        'install',
        'write',
    ]

    whiltelisted_verbs = [
        'patch',
        'release',
    ]

    allowed_dependency = np.dep_ in allowed_deps
    verb_ancestors = get_verb_ancestors(np)

    has_whitelisted_ancestor_verbs = False
    has_ioc_related_ancestor_verbs = False
    for verb_ancestor in verb_ancestors:
        is_whitelisted_verb = verb_ancestor.lemma_ in whiltelisted_verbs
        if is_whitelisted_verb:
            has_whitelisted_ancestor_verbs = True

        is_ioc_related_verb = verb_ancestor.lemma_ in ioc_related_verbs
        if is_ioc_related_verb:
            has_ioc_related_ancestor_verbs = True

    if not allowed_dependency or has_whitelisted_ancestor_verbs:
        return False

    if allowed_dependency and has_ioc_related_ancestor_verbs:
        return True


for np in doc:
    # print('np.text: {}, np.dep_: {}, np.pos_: {}, np.head.text: {}, np.head.dep_: {}, np.head.pos_: {}, np.lemma_: {}'.format(
    #     np.text, np.dep_, np.pos_, np.head.text, np.head.dep_, np.head.pos_, np.lemma_
    # ))
    if np.text == 'wannacry.exe':
        print(is_valid_candidate(np))
