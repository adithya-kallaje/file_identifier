import sys
import json
from pathlib import Path
import text_parser    


def get_header_offset(extension:str) -> int | None:
    # Open the header offset json
    try:
        with open('header_offsets.json', 'r') as f:
            header_offsets = json.load(f)
    except FileNotFoundError:
        print("Error: Header file not found")
        return None
    except json.JSONDecodeError:
        print("Error: Header file corrupted")
        return None
    
    # Return the header offset for the extension
    for extension_list in header_offsets:
        if extension_list.startswith('__'): continue
        elif extension in extension_list: return header_offsets[extension_list]
    return 0


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


def get_signature_lengths(signatures: dict) -> set:
    # Collect all unique signature byte lengths
    file_sign_lengths = set()

    for signature in signatures:
        if signature.startswith('__'):
            continue
        file_sign_lengths.add(len(bytes.fromhex(signature)))
    
    return file_sign_lengths


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


def identify_file_type(header_bytes: bytes, signature_lengths: set, signatures: dict, normalised_ext: str, file_path: str) -> str | None:
    """Match the file header against known signatures, trying longest matches first."""
    detected_ext = None
    
    for length in sorted(signature_lengths, reverse=True):
        # Convert candidate from bytes to string
        candidate = header_bytes[:length].hex()
        
        if candidate in signatures:
            detected_ext = signatures[candidate]
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

    # Extract the file extension from the filename and get the header_offset
    declared_extension = Path(file_path).suffix[1:].lower()  
    header_offset = get_header_offset(declared_extension)
    if header_offset is None: return
    
    # Collect file signatures from json and parse 
    file_signatures = get_signature_list()
    if file_signatures is None: return
    
    # Get length of the longest file_signature 
    signature_lengths = get_signature_lengths(file_signatures)
    max_length = max(signature_lengths)
 
    # Open the input file and read the header bytes
    try:
        with open(file_path, 'rb') as f:
            header_bytes = f.read(max_length)[header_offset:]
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
    detected_extension = identify_file_type(header_bytes, signature_lengths, file_signatures, normalised_extension, file_path)

    # Compare the declared extension with the detected file type
    output(detected_extension, declared_extension, normalised_extension)
        

if __name__ == '__main__':
    main()
