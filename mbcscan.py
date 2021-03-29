#!/usr/bin/env python3
import cmd, sys
import mbclib
from mbclib.mbclib import setup_src, get_mbc_external_id, get_parent_behavior
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

def print_behaviors_list(behavior_list, can_show_all=False):
    i = 0
    print('Behaviors list:\n' \
          '===============')
    
    for behavior_external_id in behavior_list:
        behavior = get_behavior_by_external_id(g_src, behavior_external_id)
        if can_show_all:
            print('')
            print_behavior_details(behavior)
        else:
            print('[' + str(i) + '] ' + behavior.name + ' (' + behavior_external_id + ')');
            
        i+=1

def print_behavior_details(behavior):
    if not behavior:
        print('[ERROR] ExternalID ' + g_args.externalId + ' is not valid.')
        raise SystemExit(1)

    print('Behavior Details:\n' \
          '=================\n' \
          'Name:\t\t' + behavior.name + '\n' \
          'MBC_ID:\t\t' + behavior.id)

    if behavior.kill_chain_phases:
        phase_str = 'Objectives:\t'
        for phase in behavior.kill_chain_phases:
            phase_shortname = phase.phase_name
            obj = get_objective_by_shortname(g_src, phase_shortname)
            if obj:
                obj_eid = get_mbc_external_id(obj)
                phase_str += obj.name + ' (' + obj_eid + ')'

    s = 'Parent:\t\t'
    if behavior.x_mitre_is_subtechnique:
        parent = get_parent_behavior(g_src, behavior.id)
        if parent:
            parent_eid = get_mbc_external_id(parent)
            s += parent.name + ' (' + parent_eid + ')'
    else:
        s += 'None'
    print(s)

    s = 'Malwares:\t'                
    malwares = get_malwares_using_behavior(g_src, behavior.id)
    if malwares:
        i = 0
        for m in malwares:
            external_id = get_mbc_external_id(m)
            s += m.name + ' (' + external_id + ')'
            i += 1
            if i < len(malwares):
                s += ', '
    else:
        s += 'None'
    print(s)

    print('\nDescription:\n' + behavior.description + '\n')

    if behavior.external_references:
        print('External references:')
        for ref in behavior.external_references:
            if ref.url:
                print('- ' + ref.url)

class MBCScanShell(cmd.Cmd):
    intro = 'Type "?" or "help" to display help.'
    prompt = '(prompt) '

    def do_list(self, arg):
        'Lists the determined behaviors on the file. Use "ls a" to list down the details.'
        can_show_all = False
        if arg == 'a' or arg == 'all':
            can_show_all = True
        print_behaviors_list(g_behaviors_list, can_show_all)

    def do_ls(self, arg):
        'Lists the determined behaviors on the file.'
        self.do_list(arg)

    def do_select(self, arg):
        'Selects and displays the details of a particular behavior.'
        if not arg:
            print('[ERROR] No selection index number specified. Try again.')
        else:
            selection_index = int(arg)
            behavior = list(g_behaviors_dict.values())[selection_index]
            print('')
            print_behavior_details(behavior)
            print('')

    def do_query(self, arg):
        'Queries and prints the detail by external_id.'
        behavior = get_behavior_by_external_id(g_src, arg.upper())
        if behavior:
            print_behavior_details(behavior)
        else:
            objective = get_objective_by_external_id(g_src, arg.upper())
            if objective:
                print_behavior_details(objective)

    def do_q(self, args):
        'Queries and prints the detail by external_id.'
        self.do_query(args)

    def do_s(self, arg):
        'Selects and displays the details of a particular behavior.'
        self.do_select(arg)

    def do_exit(self, arg):
        'Exits the program'
        return True

if __name__ == '__main__':    
    parser = ArgumentParser(description='MBC Tool')
    # parser.add_argument('input',
    #                     help='The ID to search for.')
    parser.add_argument('-i',
                        '--id',
                        help='The ID to search for.')
    parser.add_argument('-e',
                        '--externalid',
                        help='The external ID to search for.')

    g_args = parser.parse_args()

    g_src = setup_src('./mbclib/mbc-stix2/')

    g_behaviors_list = { 'C0016.001', 'C0012.002', 'E1010' }
    print_behaviors_list(g_behaviors_list)

    MBCScanShell().cmdloop()
    
    # malware = get_malware_by_id(src, 'malware--36e75009-8fd6-467a-aa8c-c6a4d3511dfa')
    # malwares = get_behaviors_used_by_malware(src ,malware.id)
    # for m in malwares:
    #     print(str(m))

    # print('=======')
    # behavior = get_behavior_by_external_id(src, 'B0031')
    # behaviors = get_malwares_using_behavior(src, behavior.id)
    # for b in behaviors:
    #     print(str(b))

