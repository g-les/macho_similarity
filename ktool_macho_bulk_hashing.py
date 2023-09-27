import sys
import ktool
from refinery import Unit,machometa
from hashlib import md5
from io import BytesIO
import xml.etree.ElementTree as ET
import argparse
import os
import csv


def main():
	enriched_machos = []
	list1 = []
	parser = argparse.ArgumentParser(description="Macho Feature Extraction for clustering and hunting.")
	parser.add_argument("-f", "--file", help="Specify file to parse", metavar="<file>", required=False)
	parser.add_argument("-d", "--directory", help="Specify a directory to run this on", metavar="<directory>", required=False)
	parser.add_argument("-p", "--print-directory", help="Print output during bulk run" )
	parser.add_argument("-o", "--output", help="Name of CSV", metavar="<file>", required=False)
	args = parser.parse_args()

	if args.directory:
		print("Extracting features from the Machos for your detection leisure")
		directory = args.directory
		for root,d_names,f_names in os.walk(directory):
			for f in f_names:
				if not f.startswith("."):
					filepath = os.path.join(root, f)
					try:
						list1 = macho_hashing(filepath)
						stripped_list = list(filter(None, list1))
						enriched_machos.append(stripped_list)
						print("\tTarget File: \t" + list1[0])
						print("\tFile MD5: \t" + list1[1])
						print("\tSig Name: \t" + list1[2])
						print("\tDylib_Hash: \t" + list1[3])
						print("\tImport Hash: \t" + list1[4])
						print("\tExport Hash: \t" + list1[5])
						print("\tEntitlement Hash: \t" + list1[6])
						print("\t\n")
					except:
						continue

		if args.output:
			with open(args.output, 'w') as f:
				written = csv.writer(f)
				written.writerow(["File", "File Hash", "Sig Name", "Dylib Hash", "Import Hash", "ExpHash", "Entitlement Hash"])
				written.writerows(enriched_machos)

	else:
		result = macho_hashing(args.file)
		if result:
			print("\tTarget File: \t" + result[0])
			print("\tFile MD5: \t" + result[1])
			print("\tSig Name: \t" + result[2])
			print("\tDylib_Hash: \t" + result[3])
			print("\tImport Hash: \t" + result[4])
			print("\tExport Hash: \t" + result[5])
			print("\tEntitlement Hash: \t" + result[6])

def macho_hashing(target):

	dylib_list = []
	import_list = []
	export_list = []
	file_hash = ""
	dylib_hash = ""
	import_hash = ""
	exphash = ""


	target_macho = open(target, mode="rb")
	contents = target_macho.read()
	file_hash = md5(contents).hexdigest()
	try:
		ktoolimage = ktool.load_image(fp=target_macho)
	except:
		print("not a macho")
		return

	for lib in ktoolimage.linked_images:
		dylib_list.append(lib.install_name.lower())
	dylib_list = sorted(dylib_list)
	dylib_list = list(dict.fromkeys(dylib_list))
	dylib_hash = md5(",".join(dylib_list).encode()).hexdigest()


	for imp in ktoolimage.imports:
		import_list.append(imp.name.lower())
	import_list = sorted(import_list)
	import_list = list(dict.fromkeys(import_list))
	import_hash = md5(",".join(import_list).encode()).hexdigest()

	for exp in ktoolimage.exports:
		export_list.append(exp.name.lower())
	export_list = sorted(export_list)
	export_list = list(dict.fromkeys(export_list))
	exphash = md5(",".join(export_list).encode()).hexdigest()

	#Parse signatures
	parsed_macho = machometa()
	parsed_sig = parsed_macho.parse_signature(ktoolimage)
	if parsed_sig:
		is_adhoc = parsed_sig.get('AdHocSigned')
		sig_idenfitier = parsed_sig.get('SignatureIdentifier')

		if is_adhoc:
			str_index = sig_idenfitier.rfind('-')
			sig_idenfitier = sig_idenfitier[:str_index]
		else:
			sig_idenfitier = sig_idenfitier

	#Parse Entitlements
		entitlement_list = []
		if parsed_sig.get('Entitlements'):
			entitlement_xml = parsed_sig.get('Entitlements')
			parsed_xml = ET.fromstring(entitlement_xml)

			for array_item in parsed_xml.iter('array'):
				request = array_item.findall('string')
				for i in request:
					entitlement_list.append(i.text.lower())

			for key_item in parsed_xml.iter('key'):
				entitlement_list.append(key_item.text.lower())

			entitlement_list = sorted(entitlement_list)
			entitlement_list = list(dict.fromkeys(entitlement_list))
			ent_hash = md5(",".join(entitlement_list).encode()).hexdigest()
		else:
			ent_hash = "No Entitlements"
	else:
		sig_idenfitier = "Not Signed"
		ent_hash = "Not Signed"
	target_macho.close()

	sig_list = [target,file_hash,sig_idenfitier,dylib_hash,import_hash,exphash,ent_hash]
	return sig_list

if __name__ == "__main__":
    main()
