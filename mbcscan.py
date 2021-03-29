#!/usr/bin/env python3
import cmd, sys
from mbclib.mbclib import *
from argparse import ArgumentParser

g_args = None
g_behaviors_list = None
g_behavior_dict = {}

def print_behaviors_list(behavior_list):
    for behavior_external_id in behavior_list:
        if behavior_external_id in g_behavior_dict.keys():
            behavior = g_behavior_dict[behavior_external_id]
        else:
            behavior = get_behavior_by_external_id(src, behavior_external_id)
            if not behavior:
                print('[ERROR] ExternalID ' + behavior_external_id + ' is not valid.')
                raise SystemExit(1)

            g_behavior_dict[behavior_external_id] = behavior

        print('behavior: ' + behavior.name + ' (' + behavior_external_id + ')');

class MBCScanShell(cmd.Cmd):
    intro = 'Intro. Type "?" for help.'
    prompt = '(prompt) '

    def do_print_behaviors_list(self, arg):
        print_behaviors_list(g_behaviors_list)

    def do_print_behavior(self, arg):
        'Prints behavior details'
        behavior = get_behavior_by_external_id(src, g_args.externalid)
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
                obj = get_objective_by_shortname(src, phase_shortname)
                if obj:
                    obj_eid = get_mbc_external_id(obj)
                    phase_str += obj.name + ' (' + obj_eid + ')'

        if behavior.x_mitre_is_subtechnique:
            parent = get_parent_behavior(src, behavior.id)
            if parent:
                parent_eid = get_mbc_external_id(parent)
                print('Parent:\t\t' + parent.name + ' (' + parent_eid + ')')

        print('\nDescription:\n' + behavior.description + '\n')

        i = 0
        if behavior.external_references:
            print('External references:')
            for ref in behavior.external_references:
                if ref.url:
                    print('[' + str(i) + '] ' + ref.url)
                    i += 1

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

    src = setup_src('./mbclib/mbc-stix2/')

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

