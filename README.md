# Macho Similiarity Hashing
Conceptual Methods for Finding Commonalities in Macho Files

In this repository are 2 scripts of mostly identical functionality - one based on lief, the other ktool 

The goal is to parse batch of Macho files to try and mine them for similarity based on hashes of the dylibs, the imports, or the exports (And eventually, hopefully, signature-based things like names or entitlements) 

I hope this can be a POC of some sort to eventually plug into other tooling to get used to create easier and faster pivots between Macho malware samples instead of more time intensive ventures like analyzing strings or disassembling or sandbox output 
