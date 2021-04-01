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
(0) [B0012.001] Anti-Static Analysis::Argument Obfuscation
(1) [C0003.002] Communication Micro-objective::Connect Pipe::Interprocess Communication
(2) [C0003.003] Communication Micro-objective::Read Pipe::Interprocess Communication
(3) [C0003.004] Communication Micro-objective::Write Pipe::Interprocess Communication
(4) [C0045]     File System Micro-objective::Copy File
(5) [C0047]     File System Micro-objective::Delete File
(6) [C0051]     File System Micro-objective::Read File
(7) [C0052]     File System Micro-objective::Writes File
(8) [C0034.001] Operating System Micro-objective::Set Variable::Environment Variable
(9) [C0040]     Process Micro-objective::Allocate Thread Local Storage
(10) [C0042]    Process Micro-objective::Create Mutex
(11) [C0041]    Process Micro-objective::Set Thread Local Storage Value
(12) [C0018]    Process Micro-objective::Terminate Process
    __  ___ ____   ______ _____                   
   /  |/  // __ ) / ____// ___/ _____ ____ _ ____ 
  / /|_/ // __  |/ /     \__ \ / ___// __ `// __ \
 / /  / // /_/ // /___  ___/ // /__ / /_/ // / / /
/_/  /_//_____/ \____/ /____/ \___/ \__,_//_/ /_/ 

    Type "?" r "help" to display help.
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
(mbcscan) s 3

================================================================================
Name:           Write Pipe::Interprocess Communication
================================================================================
MBC_ID:         attack-pattern--0947cd27-a2b6-466f-b47c-4d36e4ce06cb
External ID:    C0003.004
Objectives:     [OC0006] Communication Micro-objective
Parent:         [C0003] Interprocess Communication
Related:        [C0003.004] Write Pipe::Interprocess Communication, [C0003.001]
                Create Pipe::Interprocess Communication, [C0003.002] Connect
                Pipe::Interprocess Communication, [C0003.003] Read
                Pipe::Interprocess Communication
Samples:        None

External references:
- https://github.com/MBCProject/mbc-markdown/blob/v2.1/micro-behaviors/communication/inter-process.md
--------------------------------------------------------------------------------
```

To view details of other entries, use the `query` command.

```console
(mbcscan) q x0004
================================================================================
Name:           Dark Comet
================================================================================
MBC_ID:         malware--19d14868-ff81-4c8c-9a6a-c57baf7e7f52
External ID:    X0004
Objectives:     None
Parent:         None
Related:        None
Samples:        None

Description:    A Remote Access Trojan (RAT) that allows a user to control the
                system via a GUI. It has many features which allows a user to use
                it as administrative remote help tool; however, DarkComet has
                many features which can be used maliciously. DarkComet is
                commonly used to spy on the victims by taking screen captures,
                key-logging, or password stealing.

External references:
- https://github.com/MBCProject/mbc-markdown/blob/v2.1/xample-malware/dark-comet.md
- https://en.wikipedia.org/wiki/DarkComet
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
External ID:    B0012.001
Objectives:     [OB0002] Anti-Static Analysis
Parent:         [B0012] Disassembler Evasion
Related:        [B0012.002] Conditional Misdirection, [B0012.001] Argument
                Obfuscation, [B0012.005] VBA Stomping, [B0012.003] Value
                Dependent Jumps, [B0012.004] Variable Recomposition
Samples:        None

Description:    Simple number or string arguments to API calls are calculated at
                runtime, making linear disassembly more difficult.

External references:
- https://github.com/MBCProject/mbc-markdown/blob/v2.1/anti-static-analysis/evade-disassembler.md
--------------------------------------------------------------------------------

================================================================================
Name:           Connect Pipe::Interprocess Communication
================================================================================
MBC_ID:         attack-pattern--c1e8e932-3864-444e-b56b-70292bb7695c
External ID:    C0003.002
Objectives:     [OC0006] Communication Micro-objective
Parent:         [C0003] Interprocess Communication
Related:        [C0003.004] Write Pipe::Interprocess Communication, [C0003.001]
                Create Pipe::Interprocess Communication, [C0003.002] Connect
                Pipe::Interprocess Communication, [C0003.003] Read
                Pipe::Interprocess Communication
Samples:        None

External references:
- https://github.com/MBCProject/mbc-markdown/blob/v2.1/micro-behaviors/communication/inter-process.md
--------------------------------------------------------------------------------

================================================================================
Name:           Read Pipe::Interprocess Communication
================================================================================
MBC_ID:         attack-pattern--d6e1b096-1595-47e7-8230-223aa9cad622
External ID:    C0003.003
Objectives:     [OC0006] Communication Micro-objective
Parent:         [C0003] Interprocess Communication
Related:        [C0003.004] Write Pipe::Interprocess Communication, [C0003.001]
                Create Pipe::Interprocess Communication, [C0003.002] Connect
                Pipe::Interprocess Communication, [C0003.003] Read
                Pipe::Interprocess Communication
Samples:        None

External references:
- https://github.com/MBCProject/mbc-markdown/blob/v2.1/micro-behaviors/communication/inter-process.md
--------------------------------------------------------------------------------
...
```

## Dependencies

* [Capa](https://github.com/fireeye/capa) - MBCScan uses the related MBR behaviors that Capa detects from the given file
* [mbclib](https://github.com/accidentalrebel/mbclib) - Library for querying STIX data from the the MBC-Stix2 repository


## How to Install

* Install `flare-capa` via `pip install flare-capa`. MBCScan uses Capa as a Python library.
* Install `GitPython` via `pip install GitPython`. This is used by MBCScan to retrieve needed libraries and data.

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
