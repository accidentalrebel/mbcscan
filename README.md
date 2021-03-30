# MBCScan

Scans a malware file and lists down the related MBC (Malware Behavior Catalog) details.

## Help

```console
$ ./mbcscan.py --help
usage: mbcscan.py [-h] [-i] [-a] file

Scans a file and lists down the related MBC (Malware Behavior Catalog) details.

positional arguments:
  file                  Path of file to scan.

optional arguments:
  -h, --help            show this help message and exit
  -i, --interactive     Run program interactively.
  -a, --all             List all findings in one page.
```

## Usage

It is recommended to run the program interactively:

```console
$ sha256sum test.bin
f8ad6ecb49e68ac7cf261551f01d8ef3348e347cf4239368a26bb2b3ec372904  test.bin

$ ./mbcscan.py -i test.bin
[INFO] Setting up mbc database...
[INFO] Scanning test.bin...
================================================================================
Behaviors list:
================================================================================
[0] Anti-Static Analysis::Argument Obfuscation (B0012.001)
[1] Communication Micro-objective::Connect Pipe::Interprocess Communication (C0003.002)
[2] Communication Micro-objective::Read Pipe::Interprocess Communication (C0003.003)
[3] Communication Micro-objective::Write Pipe::Interprocess Communication (C0003.004)
[4] File System Micro-objective::Copy File (C0045)
[5] File System Micro-objective::Delete File (C0047)
[6] File System Micro-objective::Read File (C0051)
[7] File System Micro-objective::Writes File (C0052)
[8] Operating System Micro-objective::Set Variable::Environment Variable (C0034.001)
[9] Process Micro-objective::Allocate Thread Local Storage (C0040)
[10] Process Micro-objective::Create Mutex (C0042)
[11] Process Micro-objective::Set Thread Local Storage Value (C0041)
[12] Process Micro-objective::Terminate Process (C0018)
    __  ___ ____   ______ _____                   
   /  |/  // __ ) / ____// ___/ _____ ____ _ ____ 
  / /|_/ // __  |/ /     \__ \ / ___// __ `// __ \
 / /  / // /_/ // /___  ___/ // /__ / /_/ // / / /
/_/  /_//_____/ \____/ /____/ \___/ \__,_//_/ /_/ 

    Type "?" r "help" to display help.
(mbcscan) Type command here
```

Type the help command to find out available commands:

```console
(mbcscan) help

Documented commands (type help <topic>):
========================================
a  exit  help  l  list  q  query  s  select
```

View the details of a specific entry with the `select` command.

```console
mbcscan) select 10

================================================================================
Name:           Create Mutex
================================================================================
MBC_ID:         attack-pattern--f21fda77-e6ff-4351-87d9-0e2f5780a1c3
Objectives:     Process Micro-objective (OC0003)
Parent:         None
Samples:        None

Description:    Micro-behaviors related to processes.

External references:
- https://github.com/MBCProject/mbc-markdown/blob/v2.1/micro-behaviors/process/README.md
--------------------------------------------------------------------------------
```

To view details of other entries, use the `query` command.

```console
(mbcscan) query OC0004

================================================================================
Name:           Data Micro-objective
================================================================================
MBC_ID:         x-mitre-tactic--408ef4fa-de24-489a-ac9e-1f51af84bf5d
Objectives:     None
Parent:         None
Samples:        None

Description:    Micro-behaviors related to malware manipulating data.

External references:
- https://github.com/MBCProject/mbc-markdown/blob/v2.1/micro-behaviors/data/README.md
--------------------------------------------------------------------------------
```

If you don't want to run the program interactively and just want to list down all behaviors at a glance:

```console
$ ./mbcscan.py -a test.bin[INFO] Setting up mbc database...
[INFO] Scanning test.bin...
================================================================================
Behaviors list:
================================================================================

================================================================================
Name:           Argument Obfuscation
================================================================================
MBC_ID:         attack-pattern--772c8a08-0dbb-4059-8459-7ac1193840bc
Objectives:     Anti-Static Analysis (OB0002)
Parent:         None
Samples:        None

Description:    Behaviors and code characteristics that prevent static analysis or make it more difficult. Simple static analysis identifies features such as embedded strings, header information, hash values, and file metadata (e.g., creation date). More involved static analysis involves the disassembly of the binary code.

Two primary resources for anti-static analysis behaviors are [[1]](#1) and [[2]](#2).

External references:
- http://unprotect.tdgt.org/index.php/Unprotect_Project
- https://github.com/knowmalware/InDepthUnpacking
- https://github.com/MBCProject/mbc-markdown/blob/v2.1/anti-static-analysis/README.md
--------------------------------------------------------------------------------

================================================================================
Name:           Connect Pipe::Interprocess Communication
================================================================================
MBC_ID:         attack-pattern--c1e8e932-3864-444e-b56b-70292bb7695c
Objectives:     Communication Micro-objective (OC0006)
Parent:         None
Samples:        None

Description:    Micro-behaviors that enable malware to communicate.

External references:
- https://github.com/MBCProject/mbc-markdown/blob/v2.1/micro-behaviors/communication/README.md
--------------------------------------------------------------------------------

...
```

## Dependencies

* [Capa](https://github.com/fireeye/capa) - MBCScan uses the related MBR behaviors that Capa detects from the given file
* [mbclib](https://github.com/accidentalrebel/mbclib) - Library for querying STIX data from the the MBC-Stix2 repository


## How to Install

First install, `flare-capa` via `pip install flare-capa`. MBCScan uses Capa as a Python library.

Clone the repository and then run the `mbcscan.py` script. The script would automatically download and configure it's dependencies.

```console
$ git clone https://github.com/accidentalrebel/mbcscan.git
$ cd mbscan/
$ python3 ./mbscan.py
[INFO] Installing mbclib...
[INFO] Installing mbc-stix2...
[INFO] Installing capa-rules...
usage: mbcscan.py [-h] [-i] [-a] file
```

## Contributing
Feel free to submit a pull request if you want to improve this tool!
