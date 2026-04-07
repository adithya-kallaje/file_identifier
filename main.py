import json
import glob
import readline
from pathlib import Path
import text_parser
import re
from zipfile import ZipFile
from zipfile import BadZipFile
import olefile
import magic


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


def get_signature_list() -> dict | None:
    # Open and return the file signature json
    try:
        with open('data/file_signatures.json', 'r') as signature_file:
            return json.load(signature_file)
    except FileNotFoundError:
        print("Signatures file not found")
        return None
    except json.JSONDecodeError:
        print("Error: Signatures file corrupted")
        return None


def normalise_extension(extension: str) -> str:
    # Open aliases file
    try:
        with open('data/extension_aliases.json', 'r') as aliases_file:
            aliases_list = json.load(aliases_file)
    except FileNotFoundError:
        print("Error: Aliases file not found")
        return None
    except json.JSONDecodeError:
        print("Error: Aliases file corrupted")
        return None
    
    # Search through the alias file 
    for extensions in aliases_list:
        if 'aliases' in extensions and extension in extensions['aliases']:
            return extensions['canonical']
    return extension


def identify_file_type(header_bytes: bytes, normalised_ext: str, file_path: str) -> str | None:
    signatures_list = get_signature_list()
    if signatures_list is None: return
    
    detected_ext = None
    detected_ext_length = 0
    
    # Iterate through all file types
    for files_types in signatures_list:
        if files_types.startswith('__'): continue
        
        for signatures in signatures_list[files_types]:
            header_offset = signatures["offset"] * 2
            matching_signatures = '.' * header_offset + signatures["signature"]
            
            if re.match(matching_signatures, header_bytes.hex()) and len(matching_signatures) > detected_ext_length:
                detected_ext = files_types
                detected_ext_length = len(matching_signatures)
                
    if detected_ext == "zip":
        detected_ext = inspect_zip_container(file_path)
               
    elif detected_ext == "doc":
        detected_ext = inspect_ole_container(file_path)
           
    if detected_ext == None or detected_ext != normalised_ext:
        detected_ext = use_magic_lib(file_path, normalised_ext, detected_ext)
        
    if detected_ext == None or detected_ext != normalised_ext:        
        # Check for text_parsing if original detection resulted in failure or mismatch
        detected_ext =  text_parser.text_based_format_detection(file_path, detected_ext)  
    
    return detected_ext


def inspect_zip_container(file_path: str) -> str | None:
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
    try:
        ole = olefile.OleFileIO(file_path)
        for entry in ole.listdir():
            for inner_entry in entry:
                if inner_entry in OLE_FILE_MAP: return OLE_FILE_MAP.get(inner_entry)
                
        ole.close()
        return "doc"
    
    except olefile.olefile.NotOleFileError:
        print("Error opening OLE file") 
        return None   


def use_magic_lib(file_path:str, given_file_ext:str, detected_file_ext:str) -> str | None:
    try:
        with open('data/magic_values.json', 'r') as file:
            magic_values = json.load(file)
            
        file_magic_value = magic.from_file(file_path, mime=False)
            
        for value in magic_values:
            
            if file_magic_value.startswith(value):
                actual_magic_value = magic_values[value]
                
                if given_file_ext in actual_magic_value:return given_file_ext
                
                elif isinstance(actual_magic_value, list):
                    return ' / '.join(actual_magic_value)
                
                else: return actual_magic_value
        
        return detected_file_ext
    
    except FileNotFoundError:
        print("Error: magic_values.json file not found.")
        return None
    except PermissionError:
        print("Error: magic_values.json permission denied.")
        return None
    except re.error as e:
        print(f"Error on matching file signature: {e}")
        return None
    

DIVIDER = "-" * 40


def output(detected_extension: str, declared_extension: str, normalised_extension: str) -> None:
    print(DIVIDER)

    if detected_extension is None:
        print("Unable to detect file type")
        print(DIVIDER)
        return

    if declared_extension == '':
        print(f"Detected       : {detected_extension}")
        print("Warning        : No file extension — potential file upload vulnerability")
        print(DIVIDER)
        return

    if declared_extension != normalised_extension:
        print(f"Given type     : {declared_extension} -> {normalised_extension}")
    else:
        print(f"Given type     : {declared_extension}")

    print(f"Detected type  : {detected_extension}")
    print()

    if detected_extension == normalised_extension:
        print("Result         : Extensions match.")
    else:
        print("Result         : MISMATCH — potential file upload vulnerability.")

    print(DIVIDER)


def path_completer(text, state):
    matches = glob.glob(text + '*')
    matches = [m + '/' if Path(m).is_dir() else m for m in matches]
    return matches[state] if state < len(matches) else None


def main():
    readline.set_completer(path_completer)
    readline.set_completer_delims(' \t\n')
    readline.parse_and_bind("tab: complete")

    print("File Identifier")
    print(DIVIDER)

    while True:
        try:
            file_path = input("\nEnter file path: ").strip()
        except KeyboardInterrupt:
            print("\nExiting.")
            return

        # Extract the declared extension from the filename
        declared_extension = Path(file_path).suffix[1:].lower()

        # Read the header bytes
        try:
            with open(file_path, 'rb') as f:
                header_bytes = f.read(2500)
        except FileNotFoundError:
            print("Error: File not found.")
            continue
        except PermissionError:
            print("Error: Permission denied.")
            continue

        # Resolve any extension aliases
        normalised_extension = normalise_extension(declared_extension)
        if normalised_extension is None:
            continue

        # Identify the actual file type
        detected_extension = identify_file_type(header_bytes, normalised_extension, file_path)

        # Report the result
        output(detected_extension, declared_extension, normalised_extension)
        

if __name__ == '__main__':
    main()