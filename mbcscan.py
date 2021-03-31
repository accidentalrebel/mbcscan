#!/usr/bin/env python3
import os
from git.repo.base import Repo

if not os.path.isdir('./mbclib'):
    print('[INFO] Installing mbclib...')
    Repo.clone_from("https://github.com/accidentalrebel/mbclib", "mbclib")
if not os.path.isdir('./mbclib/mbc-stix2'):
    print('[INFO] Installing mbc-stix2...')
    Repo.clone_from("https://github.com/MBCProject/mbc-stix2", "./mbclib/mbc-stix2")
if not os.path.isdir('./capalib/capa-rules'):
    print('[INFO] Installing capa-rules...')
    Repo.clone_from("https://github.com/fireeye/capa-rules", "./capalib/capa-rules")

    for root, dirs, files in os.walk("./capalib/capa-rules"):
        for file in files:
            if not file.endswith(".yml"):
                filepath = os.path.join(root, file)
                os.remove(filepath)

import cmd, sys
import mbclib
import re
import textwrap
from capalib.capalib import *
from mbclib.mbclib import setup_src, get_mbc_external_id, get_parent_behavior, get_objective_by_external_id, get_malware_by_external_id, get_children_of_behavior
from argparse import ArgumentParser

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
    return get_obj_cached(src, g_behaviors_dict, behavior_external_id, mbclib.mbclib.get_behavior_by_external_id)

def get_objective_by_shortname(src, phase_shortname):
    return get_obj_cached(src, g_objectives_dict, phase_shortname, mbclib.mbclib.get_objective_by_shortname)

def get_malwares_using_behavior(src, behavior_id):
    return get_obj_cached(src, g_malwares_dict, behavior_id, mbclib.mbclib.get_malwares_using_behavior)

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
        print('[Error] Selection index ' + str(selection_index) + ' does not exist.')
        return 
    
    behavior = list(g_behaviors_dict.values())[selection_index]
    print('')
    print_obj_details(behavior)
    print('')

def print_behaviors_list(behavior_list, can_show_all=False):
    i = 0
    print(('=' * 80) + '\n'+ \
          'Behaviors list:\n' + \
          ('=' * 80))
    
    for behavior_external_id in behavior_list:
        behavior = get_behavior_by_external_id(g_src, behavior_external_id)
        if can_show_all:
            print('')
            print_obj_details(behavior)
        else:
            phase_name = behavior.kill_chain_phases[0].phase_name
            obj = get_objective_by_shortname(g_src, phase_name)
            print('(' + str(i) + ') [' + behavior_external_id + ']\t' + obj.name + '::' + behavior.name)
            
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
        print('[ERROR] Obj not provided.')
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
            print('[ERROR] No selection index number specified. Try again.')
        else:
            try:
                select(arg)
            except ValueError:
                print('[ERROR] Selection index should be a number. Try again.')

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
    # parser.add_argument('-q',
    #                     '--query',
    #                     help='The external ID to search for.')

    g_args = parser.parse_args()

    print('[INFO] Setting up mbc database...')
    
    g_src = setup_src('./mbclib/mbc-stix2/')
    g_behaviors_list = []

    print('[INFO] Scanning ' + g_args.file + '...')
    
    capa = capa_details(g_args.file)

    if len(capa['MBC']) > 0:
        for mbc_key in capa['MBC'].keys():
            for d in capa['MBC'][mbc_key]:
                external_ids = re.findall('\[(.*?)\]', d)
                if len(external_ids) > 0:
                    external_id = external_ids[0]
                    g_behaviors_list.append(external_id)
    else:
        print('No MBC determined from file.')
        sys.exit()

    print_behaviors_list(g_behaviors_list, g_args.all)
    
    if g_args.interactive:
        MBCScanShell().cmdloop()

