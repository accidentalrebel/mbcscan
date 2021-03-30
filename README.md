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
$ python3 mbcscan.py -i test.bin
[INFO] Setting up mbc database...
[INFO] Scanning test.bin...
    __  ___ ____   ______ _____                   
   /  |/  // __ ) / ____// ___/ _____ ____ _ ____ 
  / /|_/ // __  |/ /     \__ \ / ___// __ `// __ \
 / /  / // /_/ // /___  ___/ // /__ / /_/ // / / /
/_/  /_//_____/ \____/ /____/ \___/ \__,_//_/ /_/ 

    Type "?" r "help" to display help.
(mbcscan)  Type command here
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
(mbcscan) select 0

================================================================================
Name:           Check String
================================================================================
MBC_ID:         attack-pattern--9398839c-520f-4aab-9c81-92d6518800e7
Objectives:     Data Micro-objective (OC0004)
Parent:         None
Samples:        None

Description:    Micro-behaviors related to malware manipulating data.

External references:
- https://github.com/MBCProject/mbc-markdown/blob/v2.1/micro-behaviors/data/README.md
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
$ ./mbcscan.py -a test.bin
[INFO] Setting up mbc database...
[INFO] Scanning test.bin...
================================================================================
Behaviors list:
================================================================================

================================================================================
Name:           Check String
================================================================================
MBC_ID:         attack-pattern--9398839c-520f-4aab-9c81-92d6518800e7
Objectives:     Data Micro-objective (OC0004)
Parent:         None
Samples:        None

Description:    Micro-behaviors related to malware manipulating data.

External references:
- https://github.com/MBCProject/mbc-markdown/blob/v2.1/micro-behaviors/data/README.md
--------------------------------------------------------------------------------

================================================================================
Name:           Base64::Encode Data
================================================================================
MBC_ID:         attack-pattern--1dd62131-bc8e-4de7-b68a-1ea4c6b44c03
Objectives:     Data Micro-objective (OC0004)
Parent:         None
Samples:        None

Description:    Micro-behaviors related to malware manipulating data.

External references:
- https://github.com/MBCProject/mbc-markdown/blob/v2.1/micro-behaviors/data/README.md
--------------------------------------------------------------------------------
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
