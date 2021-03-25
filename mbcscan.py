#!/usr/bin/env python3
import sys
from mbclib.mbclib import setup_src, get_behavior_by_id
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

    if args.id:
        if 'malware--' in args.id:
            malware = get_malware_by_id(src, args.id)
            print(str(malware))
        elif 'attack-pattern--' in args.id:
            behavior = get_behavior_by_id(src, args.id)
            print(str(behavior))
        else:
            print('[ERROR] ID ' + args.id + ' is not valid.')
            raise SystemExit(1)
    elif args.externalid:
        behavior = mbclib.get_behavior_by_external_id(src, args.externalid)
        if behavior:
            print(str(behavior))
        else:
            print('[ERROR] ExternalID ' + args.externalId + ' is not valid.')
            raise SystemExit(1)

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

