#!/usr/bin/env python3
import sys
from mbclib.mbclib import *
from argparse import ArgumentParser

if __name__ == '__main__':
    parser = ArgumentParser(description='MBC Tool')
    parser.add_argument('-i',
                        '--id',
                        help='The ID to search for.')
    parser.add_argument('-e',
                        '--externalid',
                        help='The external ID to search for.')

    args = parser.parse_args()

    src = setup_src('./mbclib/mbc-stix2/')

    behavior = get_behavior_by_external_id(src, args.externalid)
    if not behavior:
        print('[ERROR] ExternalID ' + args.externalId + ' is not valid.')
        raise SystemExit(1)

    print('Behavior Details:\n' \
          '=================\n' \
          'Name:\t' + behavior.name + '\n' \
          'MBC_ID:\t' + behavior.id + '\n' \
          'Desc:\t' + behavior.description)

    if behavior.x_mitre_is_subtechnique:
        rels = get_behavior_relationships(src, behavior.id)
        for r in rels:
            print(str(r))

    sys.exit()

    # malware = get_malware_by_id(src, 'malware--36e75009-8fd6-467a-aa8c-c6a4d3511dfa')
    # malwares = get_behaviors_used_by_malware(src ,malware.id)
    # for m in malwares:
    #     print(str(m))

    # print('=======')
    # behavior = get_behavior_by_external_id(src, 'B0031')
    # behaviors = get_malwares_using_behavior(src, behavior.id)
    # for b in behaviors:
    #     print(str(b))

