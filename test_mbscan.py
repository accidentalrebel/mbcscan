from mbcscan import *
import subprocess
import json

bid = 'attack-pattern--295a3b88-2a7e-4bae-9c50-014fce6d5739'
eid = 'B0007'
mid = 'malware--36e75009-8fd6-467a-aa8c-c6a4d3511dfa'

def test_main():
    x = subprocess.check_output('./mbcscan.py -i ' + bid, shell=True)
    x = json.loads(x)
    assert x['type'] == 'attack-pattern' in x['id'] == bid
