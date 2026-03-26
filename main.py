import sys
import json
from pathlib import Path
import text_parser    
from re import match


def get_signature_list() -> bytes:
    # Open and return the file signature json
    try:
        with open('file_signatures.json', 'r') as signature_file:
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
        with open('extension_aliases.json', 'r') as aliases_file:
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


def identify_file_type(header_bytes: bytes, signatures: dict, normalised_ext: str, file_path: str) -> str | None:
    detected_ext = None
    
    sorted_signatures = dict(sorted(signatures.items(), key=lambda x: len(x[0]), reverse=True))
    
    for signature in sorted_signatures:
        if signature.startswith('__'): continue
        
        header_offset = signatures[signature][0] * 2
        matching_signature = '.' * header_offset + signature
        
        if match(matching_signature, header_bytes.hex()): 
            detected_ext = signatures[signature][1]
            break
        

    if detected_ext == None or detected_ext != normalised_ext:        
        # Read the input file
        with open(file_path, 'rb') as f:
            text_content = f.read()
        
        # Check for text_parsing if original detection resulted in failure or mismatch
        return text_parser.text_based_format_detection(text_content, detected_ext)
    
    return detected_ext


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
    
    # Collect file signatures from json and parse 
    file_signatures = get_signature_list()
    if file_signatures is None: return
 
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
    detected_extension = identify_file_type(header_bytes, file_signatures, normalised_extension, file_path)

    # Compare the declared extension with the detected file type
    output(detected_extension, declared_extension, normalised_extension)
        

if __name__ == '__main__':
    main()
