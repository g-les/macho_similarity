# Macho Similiarity Hashing
Conceptual Methods for Finding Commonalities in Macho Files

In this repository are 2 scripts of mostly identical functionality - one based on lief, the other ktool 

The goal is to parse batch of Macho files to try and mine them for similarity based on hashes of the dylibs, the imports, or the exports (And eventually, hopefully, signature-based things like names or entitlements) 

I hope this can be a POC of some sort to eventually plug into other tooling to get used to create easier and faster pivots between Macho malware samples instead of more time intensive ventures like analyzing strings or disassembling or sandbox output 


## Usage 

Install dependencies (lief is the easiest most likely for most) point, and click! 

```
python3 lief_macho_bulk_hashing.py -h
usage: lief_macho_bulk_hashing.py [-h] [-d <directory>] [-f <file>] [-o <file>]

Macho Feature Extraction for clustering and hunting.

optional arguments:
  -h, --help            show this help message and exit
  -d <directory>, --directory <directory>
                        Specify a directory to run this on
  -f <file>, --file <file>
                        Specify file to parse
  -o <file>, --output <file>
                        Name of CSV

```

Exazmple Single File Output
```
python3 lief_macho_bulk_hashing.py -f iContact.pkg 
	Target File: 	iContact.pkg
	File MD5: 		b0611b1df7f8516ad495cd2621d273b9
	Sig Name: 		mac
	Dylib Hash: 	e78081f55c33da0ffae6ea2c9d31808d
	Import Hash: 	7705c5a62a40e30f792aa3e0eace755d
	Export Hash: 	7f3b75c82e3151fff6c0a55b51cd5b94
```
