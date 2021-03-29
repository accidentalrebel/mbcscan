#!/usr/bin/env python3

import json
import collections

import capa.main
import capa.rules
import capa.engine
import capa.render
import capa.features
import capa.render.utils as rutils
from capa.engine import *
from capa.render import convert_capabilities_to_result_document

# edit this to set the path for file to analyze and rule directory
RULES_PATH = "./capalib/capa-rules/"

# load rules from disk
rules = capa.main.get_rules(RULES_PATH, disable_progress=True)
rules = capa.rules.RuleSet(rules)

def render_mbc(doc, ostream):
    """
    example::
        {'MBC': {'ANTI-BEHAVIORAL ANALYSIS': ['Debugger Detection::Timing/Delay Check '
                                      'GetTickCount [B0001.032]',
                                      'Emulator Detection [B0004]',
                                      'Virtual Machine Detection::Instruction '
                                      'Testing [B0009.029]',
                                      'Virtual Machine Detection [B0009]'],
         'COLLECTION': ['Keylogging::Polling [F0002.002]'],
         'CRYPTOGRAPHY': ['Encrypt Data::RC4 [C0027.009]',
                          'Generate Pseudo-random Sequence::RC4 PRGA '
                          '[C0021.004]']}
        }
    """
    ostream["MBC"] = dict()
    objectives = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        if not rule["meta"].get("mbc"):
            continue

        mbcs = rule["meta"]["mbc"]
        if not isinstance(mbcs, list):
            raise ValueError("invalid rule: MBC mapping is not a list")

        for mbc in mbcs:
            objective, _, rest = mbc.partition("::")
            if "::" in rest:
                behavior, _, rest = rest.partition("::")
                method, _, id = rest.rpartition(" ")
                objectives[objective].add((behavior, method, id))
            else:
                behavior, _, id = rest.rpartition(" ")
                objectives[objective].add((behavior, id))

    for objective, behaviors in sorted(objectives.items()):
        inner_rows = []
        for spec in sorted(behaviors):
            if len(spec) == 2:
                behavior, id = spec
                inner_rows.append("%s %s" % (behavior, id))
            elif len(spec) == 3:
                behavior, method, id = spec
                inner_rows.append("%s::%s %s" % (behavior, method, id))
            else:
                raise RuntimeError("unexpected MBC spec format")
        ostream["MBC"].setdefault(objective.upper(), inner_rows)

def render_dictionary(doc):
    ostream = dict()
    render_mbc(doc, ostream)
    return ostream

# ==== render dictionary helpers
def capa_details(file_path, output_format="dictionary"):

    # extract features and find capabilities
    extractor = capa.main.get_extractor(file_path, "auto", capa.main.BACKEND_VIV, disable_progress=True)
    capabilities, counts = capa.main.find_capabilities(rules, extractor, disable_progress=True)

    # collect metadata (used only to make rendering more complete)
    meta = capa.main.collect_metadata("", file_path, RULES_PATH, "auto", extractor)
    meta["analysis"].update(counts)

    doc = convert_capabilities_to_result_document(meta, rules, capabilities)
    capa_output = render_dictionary(doc)

    return capa_output
