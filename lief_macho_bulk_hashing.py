import sys
import lief
from hashlib import md5
import argparse
import os
import sys
import csv


def main():

	enriched_machos = []

	parser = argparse.ArgumentParser(description="Macho Feature Extraction for clustering and hunting.")
	parser.add_argument("-d", "--directory", help="Specify a directory to run this on", metavar="<directory>", required=False)
	parser.add_argument("-f", "--file", help="Specify file to parse", metavar="<file>", required=False)
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
						print("\tDylib Hash: \t" + list1[3])
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
		if result is not None:
			print("\tTarget File: \t" + result[0])
			print("\tFile MD5: \t" + result[1])
			print("\tSig Name: \t" + result[2])
			print("\tDylib Hash: \t" + result[3])
			print("\tImport Hash: \t" + result[4])
			print("\tExport Hash: \t" + result[5])



def macho_hashing(target):

	dylibs = []
	sorted_lowered_imps = []
	sorted_lowered_dylibs = []
	exp_list = []
	sym_list = []
	file_hash = ""
	dylib_hash = ""
	import_hash = ""
	exphash = ""



	try:
		parsed_macho = lief.parse(target)
		for lib in parsed_macho.libraries:
			sorted_lowered_dylibs.append(lib.name.lower())
		sorted_lowered_dylibs = sorted(sorted_lowered_dylibs)
		sorted_lowered_dylibs = list(dict.fromkeys(sorted_lowered_dylibs))
		dylib_hash = md5(",".join(sorted_lowered_dylibs).encode()).hexdigest()

		for imp in parsed_macho.imported_functions:
			sorted_lowered_imps.append(imp.name.lower())
		sorted_lowered_imps = sorted(sorted_lowered_imps)
		sorted_lowered_imps = list(dict.fromkeys(sorted_lowered_imps))
		import_hash = md5(",".join(sorted_lowered_imps).encode()).hexdigest()

		for exp in parsed_macho.exported_symbols:
			exp_list.append(exp.name.lower())
		exp_list = sorted(exp_list)
		exp_list = list(dict.fromkeys(exp_list))
		exphash = md5(",".join(exp_list).encode()).hexdigest()


		target_macho = open(target, mode="rb")
		contents = target_macho.read()
		file_hash = md5(contents).hexdigest()


		if parsed_macho.has_code_signature:

		  cs_sign_dir_offset = parsed_macho.code_signature.data_offset

		  # read the big CS directory & get ptr to 0th blob
		  target_macho.seek(cs_sign_dir_offset)
		  cs_dir_bytes = target_macho.read(0x20)
		  jump_to_blob = cs_dir_bytes[19]

		  # read the 0th blob and look for ident ofset
		  target_macho.seek(cs_sign_dir_offset+jump_to_blob)
		  first_codesign_blob = target_macho.read(0x20)
		  jump_to_ident = first_codesign_blob[23]

		  # read identifier string
		  target_macho.seek(cs_sign_dir_offset+jump_to_blob+jump_to_ident)
		  ident_str = target_macho.read(0x30)
		  sig_name = str(ident_str)
		  sig_name = sig_name.split('\\x00')[0]
		  sig_name = sig_name[2:]
		  sig_name = sig_name.split('-')[0]
		else:
		  sig_name = "Not Signed"
		target_macho.close()

	except:
		print("not a macho")
		return

	listicle = [target,file_hash,sig_name,dylib_hash,import_hash,exphash]
	return listicle
main()
