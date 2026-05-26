import json
from pathlib import Path
import text_parser
import re
from zipfile import ZipFile
from zipfile import BadZipFile
import olefile
import magic
import argparse


MIMETYPE_MAP = {                                                                                                                                                           
    "application/epub+zip": "epub",                                                                                                                                        
    'application/vnd.oasis.opendocument.presentation': "odp",
    'application/vnd.oasis.opendocument.text': "odt",  
    'application/vnd.oasis.opendocument.text-template': "ott",
    'application/vnd.oasis.opendocument.spreadsheet': "ods",                                                                                                                                                    
}

OLE_FILE_MAP = {
    'Workbook': "xls",
    'PowerPoint Document': "ppt",
    'WordDocument': "doc"
}

DIVIDER = "-" * 40


def get_signature_list() -> dict | None:
    '''Load magic byte signatures from data/file_signatures.json.'''
    try:
        with open('data/file_signatures.json', 'r') as signature_file:
            return json.load(signature_file)
    except FileNotFoundError:
        print("Signatures file not found")
        return None
    except json.JSONDecodeError:
        print("Error: Signatures file corrupted")
        return None


def get_alias_list() -> dict | None:
    '''Load extension alias mappings from data/extension_aliases.json.'''
    try:
        with open('data/extension_aliases.json', 'r') as aliases_file:
            return json.load(aliases_file)
    except FileNotFoundError:
        print("Error: Aliases file not found")
        return None
    except json.JSONDecodeError:
        print("Error: Aliases file corrupted")
        return None
    
    
def get_magic_values_list() -> dict | None:
    '''Load libmagic string-to-extension mappings from data/magic_values.json.'''
    try:
        with open('data/magic_values.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print("Error: magic_values.json file not found.")
        return None
    except PermissionError:
        print("Error: magic_values.json permission denied.")
        return None


def normalise_extension(extension: str, aliases_list: dict) -> str:
    '''Resolve an extension to its canonical form (e.g. jpg → jpeg, dng → tiff).'''
    for extensions in aliases_list:
        if 'aliases' in extensions and extension in extensions['aliases']:
            return extensions['canonical']
    return extension


def inspect_magic_bytes(header_bytes: bytes, signatures_list: dict) -> str | None:
    '''Match file header bytes against known signatures; returns longest/most-specific match.'''
    detected_ext = None
    detected_ext_length = 0
    
    # Iterate through all file types
    for file_type in signatures_list:
        if file_type.startswith('__'): continue
        
        for signature in signatures_list[file_type]:
            header_offset = signature["offset"] * 2
            matching_signatures = '.' * header_offset + signature["signature"]
            
            if re.match(matching_signatures, header_bytes.hex()) and len(matching_signatures) > detected_ext_length:
                detected_ext = file_type
                detected_ext_length = len(matching_signatures)

    
    return detected_ext


def inspect_zip_container(file_path: str) -> str | None:
    '''Distinguish ZIP-based formats (docx, xlsx, epub, odt, etc.) by internal structure.'''
    try:
        with ZipFile(file_path, "r") as file:
            namelist = file.namelist()
            
            # Read mimetype (if it exists)
            if "mimetype" in namelist:
                mimetype_str = file.read("mimetype").decode() 
                return MIMETYPE_MAP.get(mimetype_str, "zip")
            
            # Check for a decisive filename
            for namelist_entry in namelist:
                if "word/" in namelist_entry:
                    return "docx" 
                elif "xl/" in namelist_entry:
                    return "xlsx"
                        
        return "zip"
    except BadZipFile:
        print("Zipfile corrupted")
        return None


def inspect_ole_container(file_path:str) -> str | None:
    '''Distinguish OLE2 container formats (doc, xls, ppt) by internal directory entries.'''
    ole = None
    try:
        ole = olefile.OleFileIO(file_path)
        for entry in ole.listdir():
            for inner_entry in entry:
                if inner_entry in OLE_FILE_MAP: return OLE_FILE_MAP.get(inner_entry)
        return "doc"

    except olefile.olefile.NotOleFileError:
        print("Error opening OLE file") 
        return None   
    
    finally:
        if ole: ole.close()


def use_magic_lib(file_path:str, claimed_ext:str, actual_ext:str, magic_values: dict) -> str | None:
    '''Fallback to libmagic string matching when signature lookup is inconclusive.'''
    file_magic_value = magic.from_file(file_path, mime=False)
        
    for value in magic_values:
        if file_magic_value.startswith(value):
            actual_magic_value = magic_values[value]
            
            if claimed_ext in actual_magic_value:return claimed_ext
            
            elif isinstance(actual_magic_value, list):
                return ' / '.join(actual_magic_value)
            
            else: return actual_magic_value
    
    return actual_ext


def output(actual_extension: str, claimed_extension: str, normalised_extension: str, input_type: str, file_path: str) -> None:
    '''Print detection result — verbose for single-file mode, compact row for directory mode.'''
    if input_type == 'file':
        if actual_extension is None:
            print("Unable to detect file type")
            print(DIVIDER)
            return

        if claimed_extension == '':
            print(f"Detected       : {actual_extension}")
            print("Warning        : No file extension — potential file upload vulnerability")
            print(DIVIDER)
            return

        if claimed_extension != normalised_extension:
            print(f"Given type     : {claimed_extension} -> {normalised_extension}")
        else:
            print(f"Given type     : {claimed_extension}")

        print(f"Detected type  : {actual_extension}\n")

        if actual_extension == normalised_extension:
            print("Result         : Extensions match.")
        else:
            print("Result         : MISMATCH — potential file upload vulnerability.")

        print(DIVIDER)
        
    else:
        actual_str = actual_extension if actual_extension is not None else "UNKNOWN"
        verdict = "MISMATCH" if normalised_extension != actual_extension else "MATCH"
        print(f"{str(file_path):<50} {claimed_extension:<15} {actual_str:<15} {verdict}")


def identify_file_type(file_path: str, input_type:str, signature_list: dict, alias_list: dict, magic_values: dict) -> None:
    '''Run the full detection pipeline on a single file and report the result.'''

    # Extract the declared extension from the filename
    claimed_extension = Path(file_path).suffix[1:].lower()

    # Read the header bytes
    try:
        with open(file_path, 'rb') as f:
            header_bytes = f.read(2500)
    except FileNotFoundError:
        print("Error: File not found.")
        return
    except PermissionError:
        print("Error: Permission denied.")
        return

    # Resolve any extension aliases
    normalised_extension = normalise_extension(claimed_extension, alias_list)

    ## File detection
    
    # Check magic bytes
    actual_extension = inspect_magic_bytes(header_bytes, signature_list)
    
    # Check zip container
    if actual_extension == "zip":
            actual_extension = inspect_zip_container(file_path)
    
    # Check ole container
    elif actual_extension == "doc":
        actual_extension = inspect_ole_container(file_path)
    
    # Utilize "file" magic library
    if actual_extension == None or actual_extension != normalised_extension:
        actual_extension = use_magic_lib(file_path, normalised_extension, actual_extension, magic_values)
    
    # Check text content
    if actual_extension == None or actual_extension != normalised_extension: 
        actual_extension =  text_parser.text_based_format_detection(file_path, actual_extension, header_bytes)  

    # Report the result
    output(actual_extension, claimed_extension, normalised_extension, input_type, file_path)
    
            
def get_input():
    '''Parse CLI arguments; returns ['file'|'directory', path].'''
    parser = argparse.ArgumentParser(
                prog="A test program",
                description="A program to test how argparse works",
                epilog="This is the epilogue field"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file')
    group.add_argument('-d', '--directory')

    args = parser.parse_args()
    
    if args.file: return ['file', args.file]
    return ['directory', args.directory]  


def main():
    '''Entry point: loads data files once, then dispatches to single-file or batch mode.'''
    input = get_input()
    path = input[1]
    
    signature_list = get_signature_list()
    alias_list = get_alias_list()
    magic_values = get_magic_values_list()
    
    if signature_list is None or alias_list is None or magic_values is None: return
    
    if input[0] == 'file':
        print(DIVIDER)
        print("File Identifier")
        print(DIVIDER)
        identify_file_type(file_path=path, input_type='file', signature_list=signature_list, alias_list=alias_list, magic_values=magic_values)
    else:
        print(DIVIDER * 2)
        print("File Identifier")
        print()
        print(f"{'FILE PATH':<50} {'CLAIMED EXT':<15} {'ACTUAL EXT':<15} {'OUTPUT'}")
        print(DIVIDER * 2)
        for item_path in Path(path).iterdir():
            identify_file_type(file_path=item_path, input_type='directory', signature_list=signature_list, alias_list=alias_list, magic_values=magic_values)


if __name__ == '__main__':
    main()
