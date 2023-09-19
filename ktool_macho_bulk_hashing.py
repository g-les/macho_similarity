import sys
import ktool
from hashlib import md5
from io import BytesIO
import argparse
import os

def main():
	enriched_machos = []
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
						print("\tDylib_Hash: \t" + list1[2])
						print("\tImport Hash: \t" + list1[4])
						print("\tExport Hash: \t" + list1[5])
					except:
						continue

		print(enriched_machos)
		with open(args.output, 'w') as f:
			written = csv.writer(f)
			written.writerow(["File", "File Hash", "Sig Name", "Dylib Hash", "Import Hash", "ExpHash"])
			written.writerows(enriched_machos)

	else:
		result = macho_hashing(args.file)
		if result:
			print("\tTarget File: \t" + result[0])
			print("\tFile MD5: \t" + result[1])
			print("\tDylib_Hash: \t" + result[2])
			print("\tImport Hash: \t" + result[4])
			print("\tExport Hash: \t" + result[5])

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
		parsed_macho = ktool.load_image(fp=target_macho)
	except:
		print("not a macho")
		return

	for lib in parsed_macho.linked_images:
		dylib_list.append(lib.install_name.lower())
	dylib_list = sorted(dylib_list)
	dylib_list = list(dict.fromkeys(dylib_list))
	dylib_hash = md5(",".join(dylib_list).encode()).hexdigest()


	for imp in parsed_macho.imports:
		import_list.append(imp.name.lower())
	import_list = sorted(import_list)
	import_list = list(dict.fromkeys(import_list))
	import_hash = md5(",".join(import_list).encode()).hexdigest()

	for exp in parsed_macho.exports:
		export_list.append(exp.name.lower())
	export_list = sorted(export_list)
	export_list = list(dict.fromkeys(export_list))
	exphash = md5(",".join(export_list).encode()).hexdigest()



	target_macho.close()



	sig_list = [target,file_hash,dylib_hash,dylib_list,import_hash,exphash]
	return sig_list
main()
