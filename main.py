import sys
import json
from pathlib import Path
import text_parser    
from re import match
from zipfile import ZipFile
from zipfile import BadZipFile
import olefile


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


def get_signature_list() -> bytes:
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
            
            if match(matching_signatures, header_bytes.hex()) and len(matching_signatures) > detected_ext_length:
                detected_ext = files_types
                detected_ext_length = len(matching_signatures)
                
    if detected_ext == "zip":
        detected_ext = inspect_zip_container(file_path)
        
    if detected_ext == "doc":
        detected_ext = inspect_ole_container(file_path)
        
    if detected_ext == None or detected_ext != normalised_ext:        
        # Read the input file
        with open(file_path, 'rb') as f:
            text_content = f.read()
            
        # Check for text_parsing if original detection resulted in failure or mismatch
        return text_parser.text_based_format_detection(text_content, detected_ext)
    
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

        return "doc"
    
    except olefile.olefile.NotOleFileError:
        print("Error opening OLE file") 
        return None   


def output(detected_extension: str, declared_extension: str, normalised_extension: str) -> None:
    if detected_extension is not None:
        if declared_extension == '':
            print(f"Detected {detected_extension} from header values \nFile has no extension, potential file upload vulnerability")
            return
        
        if declared_extension != normalised_extension:
            print(f"Given file type  : {declared_extension} -> {normalised_extension}")
        else:
            print(f"Given file type  : {declared_extension}")
            
        print(f"Actual file type : {detected_extension}")
        
        if detected_extension == normalised_extension:
            print("\nExtensions match.")
            return
        else:
            print("\nMismatching file extensions. Potential file upload vulnerability.")
            return
    else:
        print("Unable to detect file type")
        return
    

def main():
    # Ensure a file path was provided
    if len(sys.argv) < 2:
        print("Usage: python main.py <file_path>")
        return

    # Get the extension from the file
    file_path = sys.argv[1]
    # file_path = "test_files/frieren"

    # Extract the file extension from the filename
    declared_extension = Path(file_path).suffix[1:].lower()  
 
    # Open the input file and read the header bytes
    try:
        with open(file_path, 'rb') as f:
            header_bytes = f.read(2500)
    except FileNotFoundError:
        print("Error: File not found.")
        return 
    except PermissionError:
        print("Error: Permission denied.")
        return 
    
    # Check for aliases
    normalised_extension = normalise_extension(declared_extension)
    if normalised_extension is None: return None
    
    # Identify the actual file type using file signatures and text_parsing
    detected_extension = identify_file_type(header_bytes, normalised_extension, file_path)

    # Compare the declared extension with the detected file type
    output(detected_extension, declared_extension, normalised_extension)
        

if __name__ == '__main__':
    main()