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
$ ./mbcscan.py -i test.bin
[INFO] Setting up mbc database...
[INFO] Scanning test.bin...
================================================================================
Behaviors list:
================================================================================
[0] Data Micro-objective::Check String (C0019)
[1] Data Micro-objective::Base64::Encode Data (C0026.001)
Type "?" or "help" to display help.
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
