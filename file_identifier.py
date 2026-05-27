import json
from pathlib import Path
import text_parser
import re
from zipfile import ZipFile
from zipfile import BadZipFile
import olefile
import magic
import argparse
from dataclasses import dataclass


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


@dataclass
class Extensions():
    '''A class to hold all extension informations for the file'''
    actual_extension: str
    claimed_extension: str
    normalized_extension: str
    

@dataclass
class Datasets():
    '''Holds the various dataset the program refers to'''
    signature_list: dict
    alias_list: dict
    magic_values: dict
    

@dataclass
class UserInput():
    '''Holds information about the user input'''
    file_path: str
    input_type: str
    write_output: str | None
    

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


def normalize_extension(extension: str, aliases_list: dict) -> str:
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


def file_output(file_extensions: Extensions) -> None:
    '''Print detection result for files'''
    
    actual_extension = file_extensions.actual_extension
    claimed_extension = file_extensions.claimed_extension
    normalized_extension = file_extensions.normalized_extension
    
    print(f"\n{DIVIDER}")
    print("File Identifier")
    print(DIVIDER)
    
    if actual_extension is None:
        print("Unable to detect file type")
        print(DIVIDER)
        return

    if claimed_extension == '':
        print(f"Detected       : {actual_extension}")
        print("Warning        : No file extension - potential file upload vulnerability")
        print(DIVIDER)
        return

    if claimed_extension != normalized_extension:
        print(f"Given type     : {claimed_extension} -> {normalized_extension}")
    else:
        print(f"Given type     : {claimed_extension}")

    print(f"Detected type  : {actual_extension}\n")

    if actual_extension == normalized_extension:
        print("Result         : Extensions match.")
    else:
        print("Result         : MISMATCH — potential file upload vulnerability.")

    print(DIVIDER)
    

def dir_output(file_extension: Extensions, file_path: str, title: bool) -> None:
    '''Print detection result for directories'''
    
    actual_extension = file_extension.actual_extension
    normalized_extension = file_extension.normalized_extension
    claimed_extension = file_extension.claimed_extension
    
    if title:
        print(f"\n{DIVIDER * 4}")
        print("File Identifier")
        print()
        print(f"{'FILE PATH':<50} {'CLAIMED EXT':<25} {'ACTUAL EXT':<25} {'OUTPUT'}")
        print(DIVIDER * 4)
    
    actual_str = actual_extension if actual_extension is not None else "UNKNOWN"
    
    if actual_str == 'UNKNOWN': verdict = 'Could Not Identify File extension'
    elif claimed_extension == '': verdict = 'No file extension - potential file upload vulnerability'
    elif actual_str == normalized_extension: verdict = 'Extensions match'
    else: verdict = 'MISMATCH — potential file upload vulnerability'
    
    claimed_str = f"{claimed_extension} -> {normalized_extension}" if claimed_extension != normalized_extension else claimed_extension
    print(f"{str(file_path):<50} {claimed_str:<25} {actual_str:<25} {verdict}")   


def identify_file_type(file_path: str, dataset: Datasets) -> Extensions:
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
    normalized_extension = normalize_extension(claimed_extension, dataset.alias_list)

    ## File detection
    
    # Check magic bytes
    actual_extension = inspect_magic_bytes(header_bytes, dataset.signature_list)
    
    # Check zip container
    if actual_extension == "zip":
            actual_extension = inspect_zip_container(file_path)
    
    # Check ole container
    elif actual_extension == "doc":
        actual_extension = inspect_ole_container(file_path)
    
    # Utilize "file" magic library
    if actual_extension == None or actual_extension != normalized_extension:
        actual_extension = use_magic_lib(file_path, normalized_extension, actual_extension, dataset.magic_values)
    
    # Check text content
    if actual_extension == None or actual_extension != normalized_extension: 
        actual_extension =  text_parser.text_based_format_detection(file_path, actual_extension, header_bytes)  
        
    # Create extensions dataclass
    file_extensions = Extensions(
        actual_extension=actual_extension, 
        claimed_extension=claimed_extension, 
        normalized_extension=normalized_extension
    )

    return file_extensions
    
    
def dispatch_identification(input: UserInput, dataset:Datasets):
    '''Calls the identification and output functions depending on the user input (dir/file)'''
    
    input_type = input.input_type
    path = input.file_path
    title = True
    
    if input_type == 'file':
        file_extension = identify_file_type(file_path=path, dataset=dataset)
        file_output(file_extensions=file_extension)
        
    elif input_type == 'directory':
        for item_path in Path(path).iterdir():
            file_extension = identify_file_type(file_path=item_path, dataset=dataset)
            
            if input.write_output:
                # Write to the file
                return
                
            else:
                dir_output(file_extension=file_extension, file_path=item_path, title=title)
                title = False
                    
            
def get_input():
    '''Parse CLI arguments; returns ['file'|'directory', path, output_path].'''
    parser = argparse.ArgumentParser(
                prog="A test program",
                description="A program to test how argparse works",
                epilog="This is the epilogue field"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file')
    group.add_argument('-d', '--directory')
    
    parser.add_argument('-o', '--output_file')

    args = parser.parse_args()
    
    input = UserInput(
        file_path= args.file if args.file else args.directory,
        input_type= 'file' if args.file else 'directory',
        write_output= args.output_file
    )
    
    return input


def main():
    '''Entry point: loads data files once, then dispatches to single-file or batch mode.'''
    input = get_input()
    
    # Get the datasets and put them in a dataclass
    signature_list = get_signature_list()
    alias_list = get_alias_list()
    magic_values = get_magic_values_list()
    
    if signature_list is None or alias_list is None or magic_values is None: return
    
    dataset = Datasets(
        signature_list=signature_list,
        alias_list=alias_list,
        magic_values=magic_values
    )
    
    dispatch_identification(input=input, dataset=dataset)


if __name__ == '__main__':
    main()
