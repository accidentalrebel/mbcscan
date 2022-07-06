#!/usr/bin/env python3
import os
from git.repo.base import Repo

import sys
sys.path.append(os.path.expanduser('~') + '/.mbcscan')
import cmd, sys
import re
import textwrap
import os
import json
import collections
import capa.main
import capa.rules
import capa.engine
import capa.render
import capa.features
import capa.render.utils as rutils
from argparse import ArgumentParser
from capa.engine import *
import capa.render.result_document as rd
import mbclib
from mbclib import setup_src, get_mbc_external_id, get_parent_behavior, get_objective_by_external_id, get_malware_by_external_id, get_children_of_behavior

g_args = None
g_behaviors_list = None
g_behaviors_dict = {}
g_objectives_dict = {}
g_malwares_dict = {}

def get_obj_cached(src, dict_to_check, id_to_check, func_to_call):
    if id_to_check in dict_to_check.keys():
        obj = dict_to_check[id_to_check]
    else:
        obj = func_to_call(src, id_to_check)
    dict_to_check[id_to_check] = obj
    
    return obj
    
def get_behavior_by_external_id(src, behavior_external_id):
    return get_obj_cached(src, g_behaviors_dict, behavior_external_id, mbclib.get_behavior_by_external_id)

def get_objective_by_shortname(src, phase_shortname):
    return get_obj_cached(src, g_objectives_dict, phase_shortname, mbclib.get_objective_by_shortname)

def get_malwares_using_behavior(src, behavior_id):
    return get_obj_cached(src, g_malwares_dict, behavior_id, mbclib.get_malwares_using_behavior)

def query(query_str):
    obj = get_behavior_by_external_id(g_src, query_str.upper())
    if not obj:
        obj = get_objective_by_external_id(g_src, query_str.upper())
    if not obj:
        obj = get_malware_by_external_id(g_src, query_str.upper())

    return obj

def select(index):
    selection_index = int(index)
    if selection_index >= len(g_behaviors_dict.values()):
        print_verbose('[Error] Selection index ' + str(selection_index) + ' does not exist.')
        return 
    
    behavior = list(g_behaviors_dict.values())[selection_index]
    print_verbose('')
    print_obj_details(behavior)
    print_verbose('')

def print_behaviors_list(behavior_list, can_show_all=False):
    i = 0
    print(('=' * 60) + '\n'+ \
          'MBC behaviors list (github.com/accidentalrebel/mbcscan):\n' + \
          ('=' * 60))
    
    for behavior_external_id in behavior_list:
        behavior = get_behavior_by_external_id(g_src, behavior_external_id)
        if can_show_all:
            print('')
            print_obj_details(behavior)
        elif hasattr(behavior, 'kill_chain_phases'):
            phase_name = behavior.kill_chain_phases[0].phase_name
            obj = get_objective_by_shortname(g_src, phase_name)
            print(str(i) + ') [' + behavior_external_id + ']\t ' + obj.name + '::' + behavior.name)
            
        i+=1

def wrap_value_text(to_split):
    splitted = textwrap.wrap(to_split, 65)
    i = 0
    j = 0
    s = ''
    for split in splitted:
        if i > 0:
            s += '\t\t'
        s += split
        if j < len(splitted) - 1:
            s += '\n'
        i += 1
        j += 1
    return s

def print_obj_details(obj):
    if not obj:
        print_verbose('[ERROR] Obj not provided.')
        raise SystemExit(1)

    print(('=' * 80) + '\n' \
          'Name:\t\t' + obj.name + '\n' \
          + ('=' * 80) + '\n' \
          'MBC_ID:\t\t' + obj.id + '\n' \
          'External ID:\t' + get_mbc_external_id(obj))

    s = 'Objectives:\t'
    if hasattr(obj, 'kill_chain_phases'):
        for phase in obj.kill_chain_phases:
            phase_shortname = phase.phase_name
            o = get_objective_by_shortname(g_src, phase_shortname)
            if o:
                obj_eid = get_mbc_external_id(o)
                s += '[' + obj_eid + '] ' + o.name
    else:
        s += 'None'
    print(s)

    parent = None
    s = 'Parent:\t\t'
    if hasattr(obj, 'x_mitre_is_subtechnique'):
        parent = get_parent_behavior(g_src, obj.id)
        if parent:
            parent_eid = get_mbc_external_id(parent)
            s += '[' + parent_eid + '] ' + parent.name
        else:
            s += 'None'
    else:
        s += 'None'
    print(s)

    if parent:
        behaviors = get_children_of_behavior(g_src, parent.id)
        i = 0
        s = ''
        for b in behaviors:
            obj_eid = get_mbc_external_id(b)
            s += '[' + obj_eid + '] ' + b.name
            i += 1
            if i < len(behaviors):
                s += ', '

        print('Related:\t' + wrap_value_text(s))
    else:
        print('Related:\tNone')

    malwares = get_malwares_using_behavior(g_src, obj.id)
    if malwares:
        i = 0
        s = ''
        for m in malwares:
            external_id = get_mbc_external_id(m)
            s += '[' + external_id + '] ' + m.name
            i += 1
            if i < len(malwares):
                s += ', '
                
        print('Samples:\t' + wrap_value_text(s) + '\n')
    else:
        print('Samples:\tNone\n')

    if hasattr(obj, 'description'):
        s = 'Description:\t' + wrap_value_text(obj.description) + '\n'
        print(s)

    if obj.external_references:
        print('External references:')
        for ref in obj.external_references:
            if ref.url:
                print('- ' + ref.url)

    print(('-' * 80))


def capa_render_mbc(doc, ostream):
    ostream["MBC"] = dict()
    objectives = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        if not rule["meta"].get("mbc"):
            continue

        mbcs = rule["meta"]["mbc"]
        if not isinstance(mbcs, list):
            raise ValueError("invalid rule: MBC mapping is not a list")

        for mbc in mbcs:
            objective = mbc['objective']
            behavior = mbc['behavior']
            method = mbc['method']
            id = mbc['id']
            if method == "":
                  objectives[objective].add((behavior, id))
            else:
                  objectives[objective].add((behavior, method, id))

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

def capa_render_dictionary(doc):
    ostream = dict()
    capa_render_mbc(doc, ostream)
    return ostream

def capa_details(file_path, output_format="dictionary"):
    if not g_args.verbose:
        sys.stdout = open(os.devnull, "w")
        sys.stderr = open(os.devnull, "w")
    
    rules_path = os.path.expanduser('~') + "/.mbcscan/capalib/capa-rules"
    rules = capa.main.get_rules([rules_path], disable_progress=True)
    rules = capa.rules.RuleSet(rules)
    
    extractor = capa.main.get_extractor(file_path, "auto", capa.main.BACKEND_VIV, [], disable_progress=True)
    capabilities, counts = capa.main.find_capabilities(rules, extractor, disable_progress=True)

    meta = capa.main.collect_metadata("", file_path, rules_path, extractor)

    doc = rd.ResultDocument.from_capa(meta, rules, capabilities)
    capa_output = capa_render_dictionary(doc)

    if not g_args.verbose:
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__

    return capa_output

class MBCScanShell(cmd.Cmd):
    intro = """    __  ___ ____   ______ _____                   
   /  |/  // __ ) / ____// ___/ _____ ____ _ ____ 
  / /|_/ // __  |/ /     \__ \ / ___// __ `// __ \\
 / /  / // /_/ // /___  ___/ // /__ / /_/ // / / /
/_/  /_//_____/ \____/ /____/ \___/ \__,_//_/ /_/ 

    Type "?" r "help" to display help."""
    prompt = '(mbcscan) '

    def do_list(self, arg):
        'Lists the determined behaviors related to the file.'
        can_show_all = False
        if arg == 'a' or arg == 'all':
            can_show_all = True
        print_behaviors_list(g_behaviors_list, can_show_all)

    def do_l(self, arg):
        'Lists the determined behaviors related to the file.'
        self.do_list(None)

    def do_a(self, arg):
        'Lists full details of all determined behaviors related to the file.'
        self.do_list('all')

    def do_select(self, arg):
        'Selects and displays the details of a particular behavior.'
        if not arg:
            print_verbose('[ERROR] No selection index number specified. Try again.')
        else:
            try:
                select(arg)
            except ValueError:
                print_verbose('[ERROR] Selection index should be a number. Try again.')

    def do_s(self, arg):
        'Selects and displays the details of a particular behavior.'
        self.do_select(arg)

    def do_query(self, arg):
        'Queries and prints the details of a behavior, objective, or malware by "id" or "external id".'
        obj = query(arg)
        if obj:
            print_obj_details(obj)
        return obj

    def do_q(self, args):
        'Queries and prints the details of a behavior, objective, or malware by "id" or "external id".'
        self.do_query(args)

    def do_exit(self, arg):
        'Exits the program.'
        return True

def print_verbose(str):
    if g_args.verbose:
        print(str)

if __name__ == '__main__':
    parser = ArgumentParser(description='Scans a malware file and lists down the related MBC (Malware Behavior Catalog) details.')
    parser.add_argument('file',
                        help='Path of file to scan.')
    parser.add_argument('-i',
                        '--interactive',
                        action='store_true',
                        help='Run program interactively.')
    parser.add_argument('-a',
                        '--all',
                        action='store_true',
                        help='List all findings in one page.')
    parser.add_argument('-v',
                        '--verbose',
                        action='store_true',
                        help='Enable verbose print statements.')

    g_args = parser.parse_args()

    if not os.path.isdir(os.path.expanduser('~') + '/.mbcscan/mbc-stix2'):
        print_verbose('[INFO] Installing mbc-stix2...')
        Repo.clone_from('https://github.com/MBCProject/mbc-stix2', os.path.expanduser('~') + '/.mbcscan/mbc-stix2')
    if not os.path.isdir(os.path.expanduser('~') + '/.mbcscan/capalib/capa-rules'):
        print_verbose('[INFO] Installing capa-rules...')
        Repo.clone_from('https://github.com/fireeye/capa-rules', os.path.expanduser('~') + '/.mbcscan/capalib/capa-rules')

        for root, dirs, files in os.walk(os.path.expanduser('~') + '/.mbcscan/capalib/capa-rules'):
            for file in files:
                if not file.endswith('.yml'):
                    filepath = os.path.join(root, file)
                    ## os.remove(filepath)

    print_verbose('[INFO] Setting up mbc database...')
    
    g_src = setup_src(os.path.expanduser('~') + '/.mbcscan/mbc-stix2/mbc/')
    g_behaviors_list = []

    print_verbose('[INFO] Scanning ' + g_args.file + '...')

    capa = capa_details(g_args.file)

    if len(capa['MBC']) > 0:
        for mbc_key in capa['MBC'].keys():
            for d in capa['MBC'][mbc_key]:
                external_id = str(d).split(" ")[-1]
                if external_id:
                   g_behaviors_list.append(external_id)
    else:
        print_verbose('No MBC determined from file.')
        sys.exit()

    print_behaviors_list(g_behaviors_list, g_args.all)
    
    if g_args.interactive:
        MBCScanShell().cmdloop()
#!/usr/bin/env python3
import os
from git.repo.base import Repo

import sys
sys.path.append(os.path.expanduser('~') + '/.mbcscan')
import cmd, sys
import re
import textwrap
import os
import json
import collections
import capa.main
import capa.rules
import capa.engine
import capa.render
import capa.features
import capa.render.utils as rutils
from argparse import ArgumentParser
from capa.engine import *
import capa.render.result_document as rd
import mbclib
from mbclib import setup_src, get_mbc_external_id, get_parent_behavior, get_objective_by_external_id, get_malware_by_external_id, get_children_of_behavior

g_args = None
g_behaviors_list = None
g_behaviors_dict = {}
g_objectives_dict = {}
g_malwares_dict = {}

def get_obj_cached(src, dict_to_check, id_to_check, func_to_call):
    if id_to_check in dict_to_check.keys():
        obj = dict_to_check[id_to_check]
    else:
        obj = func_to_call(src, id_to_check)
        dict_to_check[id_to_check] = obj
    
    return obj
    
def get_behavior_by_external_id(src, behavior_external_id):
    return get_obj_cached(src, g_behaviors_dict, behavior_external_id, mbclib.get_behavior_by_external_id)

def get_objective_by_shortname(src, phase_shortname):
    return get_obj_cached(src, g_objectives_dict, phase_shortname, mbclib.get_objective_by_shortname)

def get_malwares_using_behavior(src, behavior_id):
    return get_obj_cached(src, g_malwares_dict, behavior_id, mbclib.get_malwares_using_behavior)

def query(query_str):
    obj = get_behavior_by_external_id(g_src, query_str.upper())
    if not obj:
        obj = get_objective_by_external_id(g_src, query_str.upper())
    if not obj:
        obj = get_malware_by_external_id(g_src, query_str.upper())

    return obj

def select(index):
    selection_index = int(index)
    if selection_index >= len(g_behaviors_dict.values()):
        print_verbose('[Error] Selection index ' + str(selection_index) + ' does not exist.')
        return 
    
    behavior = list(g_behaviors_dict.values())[selection_index]
    print_verbose('')
    print_obj_details(behavior)
    print_verbose('')

def print_behaviors_list(behavior_list, can_show_all=False):
    i = 0
    print(('=' * 60) + '\n'+ \
          'MBC behaviors list (github.com/accidentalrebel/mbcscan):\n' + \
          ('=' * 60))
    
    for behavior_external_id in behavior_list:
        behavior = get_behavior_by_external_id(g_src, behavior_external_id)
        if can_show_all:
            print('')
            print_obj_details(behavior)
        elif hasattr(behavior, 'kill_chain_phases'):
            phase_name = behavior.kill_chain_phases[0].phase_name
            obj = get_objective_by_shortname(g_src, phase_name)
            print(str(i) + ') [' + behavior_external_id + ']\t ' + obj.name + '::' + behavior.name)
            
        i+=1

def wrap_value_text(to_split):
    splitted = textwrap.wrap(to_split, 65)
    i = 0
    j = 0
    s = ''
    for split in splitted:
        if i > 0:
            s += '\t\t'
        s += split
        if j < len(splitted) - 1:
            s += '\n'
        i += 1
        j += 1
    return s

def print_obj_details(obj):
    if not obj:
        print_verbose('[ERROR] Obj not provided.')
        raise SystemExit(1)

    print(('=' * 80) + '\n' \
          'Name:\t\t' + obj.name + '\n' \
          + ('=' * 80) + '\n' \
          'MBC_ID:\t\t' + obj.id + '\n' \
          'External ID:\t' + get_mbc_external_id(obj))

    s = 'Objectives:\t'
    if hasattr(obj, 'kill_chain_phases'):
        for phase in obj.kill_chain_phases:
            phase_shortname = phase.phase_name
            o = get_objective_by_shortname(g_src, phase_shortname)
            if o:
                obj_eid = get_mbc_external_id(o)
                s += '[' + obj_eid + '] ' + o.name
    else:
        s += 'None'
    print(s)

    parent = None
    s = 'Parent:\t\t'
    if hasattr(obj, 'x_mitre_is_subtechnique'):
        parent = get_parent_behavior(g_src, obj.id)
        if parent:
            parent_eid = get_mbc_external_id(parent)
            s += '[' + parent_eid + '] ' + parent.name
        else:
            s += 'None'
    else:
        s += 'None'
    print(s)

    if parent:
        behaviors = get_children_of_behavior(g_src, parent.id)
        i = 0
        s = ''
        for b in behaviors:
            obj_eid = get_mbc_external_id(b)
            s += '[' + obj_eid + '] ' + b.name
            i += 1
            if i < len(behaviors):
                s += ', '

        print('Related:\t' + wrap_value_text(s))
    else:
        print('Related:\tNone')

    malwares = get_malwares_using_behavior(g_src, obj.id)
    if malwares:
        i = 0
        s = ''
        for m in malwares:
            external_id = get_mbc_external_id(m)
            s += '[' + external_id + '] ' + m.name
            i += 1
            if i < len(malwares):
                s += ', '
                
        print('Samples:\t' + wrap_value_text(s) + '\n')
    else:
        print('Samples:\tNone\n')

    if hasattr(obj, 'description'):
        s = 'Description:\t' + wrap_value_text(obj.description) + '\n'
        print(s)

    if obj.external_references:
        print('External references:')
        for ref in obj.external_references:
            if ref.url:
                print('- ' + ref.url)

    print(('-' * 80))


def capa_render_mbc(doc, ostream):
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

def capa_render_dictionary(doc):
    ostream = dict()
    capa_render_mbc(doc, ostream)
    return ostream

def capa_details(file_path, output_format="dictionary"):
    if not g_args.verbose:
        sys.stdout = open(os.devnull, "w")
        sys.stderr = open(os.devnull, "w")
    
    rules_path = os.path.expanduser('~') + "/.mbcscan/capalib/capa-rules/"
    rules = capa.main.get_rules(rules_path, disable_progress=True)
    rules = capa.rules.RuleSet(rules)
    
    extractor = capa.main.get_extractor(file_path, "auto", capa.main.BACKEND_VIV, disable_progress=True)
    capabilities, counts = capa.main.find_capabilities(rules, extractor, disable_progress=True)

    meta = capa.main.collect_metadata("", file_path, rules_path, "auto", extractor)

    doc = rd.ResultDocument.from_capa(meta, rules, capabilities)
    capa_output = capa_render_dictionary(doc)

    if not g_args.verbose:
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__

    return capa_output

class MBCScanShell(cmd.Cmd):
    intro = """    __  ___ ____   ______ _____                   
   /  |/  // __ ) / ____// ___/ _____ ____ _ ____ 
  / /|_/ // __  |/ /     \__ \ / ___// __ `// __ \\
 / /  / // /_/ // /___  ___/ // /__ / /_/ // / / /
/_/  /_//_____/ \____/ /____/ \___/ \__,_//_/ /_/ 

    Type "?" r "help" to display help."""
    prompt = '(mbcscan) '

    def do_list(self, arg):
        'Lists the determined behaviors related to the file.'
        can_show_all = False
        if arg == 'a' or arg == 'all':
            can_show_all = True
        print_behaviors_list(g_behaviors_list, can_show_all)

    def do_l(self, arg):
        'Lists the determined behaviors related to the file.'
        self.do_list(None)

    def do_a(self, arg):
        'Lists full details of all determined behaviors related to the file.'
        self.do_list('all')

    def do_select(self, arg):
        'Selects and displays the details of a particular behavior.'
        if not arg:
            print_verbose('[ERROR] No selection index number specified. Try again.')
        else:
            try:
                select(arg)
            except ValueError:
                print_verbose('[ERROR] Selection index should be a number. Try again.')

    def do_s(self, arg):
        'Selects and displays the details of a particular behavior.'
        self.do_select(arg)

    def do_query(self, arg):
        'Queries and prints the details of a behavior, objective, or malware by "id" or "external id".'
        obj = query(arg)
        if obj:
            print_obj_details(obj)
        return obj

    def do_q(self, args):
        'Queries and prints the details of a behavior, objective, or malware by "id" or "external id".'
        self.do_query(args)

    def do_exit(self, arg):
        'Exits the program.'
        return True

def print_verbose(str):
    if g_args.verbose:
        print(str)

if __name__ == '__main__':
    parser = ArgumentParser(description='Scans a malware file and lists down the related MBC (Malware Behavior Catalog) details.')
    parser.add_argument('file',
                        help='Path of file to scan.')
    parser.add_argument('-i',
                        '--interactive',
                        action='store_true',
                        help='Run program interactively.')
    parser.add_argument('-a',
                        '--all',
                        action='store_true',
                        help='List all findings in one page.')
    parser.add_argument('-v',
                        '--verbose',
                        action='store_true',
                        help='Enable verbose print statements.')

    g_args = parser.parse_args()

    if not os.path.isdir(os.path.expanduser('~') + '/.mbcscan/mbc-stix2'):
        print_verbose('[INFO] Installing mbc-stix2...')
        Repo.clone_from('https://github.com/MBCProject/mbc-stix2', os.path.expanduser('~') + '/.mbcscan/mbc-stix2')
    if not os.path.isdir(os.path.expanduser('~') + '/.mbcscan/capalib/capa-rules'):
        print_verbose('[INFO] Installing capa-rules...')
        Repo.clone_from('https://github.com/fireeye/capa-rules', os.path.expanduser('~') + '/.mbcscan/capalib/capa-rules')

        for root, dirs, files in os.walk(os.path.expanduser('~') + '/.mbcscan/capalib/capa-rules'):
            for file in files:
                if not file.endswith('.yml'):
                    filepath = os.path.join(root, file)
                    os.remove(filepath)

    print_verbose('[INFO] Setting up mbc database...')
    
    g_src = setup_src(os.path.expanduser('~') + '/.mbcscan/mbc-stix2/')
    g_behaviors_list = []

    print_verbose('[INFO] Scanning ' + g_args.file + '...')

    capa = capa_details(g_args.file)

    if len(capa['MBC']) > 0:
        for mbc_key in capa['MBC'].keys():
            for d in capa['MBC'][mbc_key]:
                external_ids = re.findall('\[(.*?)\]', d)
                if len(external_ids) > 0:
                    external_id = external_ids[0]
                    g_behaviors_list.append(external_id)
    else:
        print_verbose('No MBC determined from file.')
        sys.exit()

    print_behaviors_list(g_behaviors_list, g_args.all)
    
    if g_args.interactive:
        MBCScanShell().cmdloop()
