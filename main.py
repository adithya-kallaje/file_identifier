import sys
import json
from pathlib import Path


def get_signature_lengths(signatures: dict) -> set:
    """Collect all unique signature byte lengths for efficient lookup."""
    file_sign_lengths = set()

    for signature in signatures:
        file_sign_lengths.add(len(bytes.fromhex(signature)))
    
    return file_sign_lengths


def identify_file_type(header_bytes: bytes, signature_lengths: set, signatures: dict) -> str | None:
    """Match the file header against known signatures, trying longest matches first."""
    for length in sorted(signature_lengths, reverse=True):
        # Convert candidate from bytes to string
        candidate = header_bytes[:length].hex()
        
        if candidate in signatures:
            return signatures[candidate]

    print("Unable to identify file type from signature.")
    return None


def normalize_extension(extension: str, aliases_list: list) -> str:
    """Resolve an extension to its canonical form using the alias table."""
    for extensions in aliases_list:
        if extension in extensions['aliases']:
            return extensions['canonical']
    return extension


def get_file_signature(file_path: str, max_length: int) -> bytes | None:
    """Read the first n bytes (enough to cover the longest known signature)"""
    try:
        with open(file_path, 'rb') as f:
            header_bytes = f.read(max_length)
    except FileNotFoundError:
        print("Error: File not found.")
        return 
    except PermissionError:
        print("Error: Permission denied.")
        return 
    
    return header_bytes


def main():
    # Ensure a file path was provided
    if len(sys.argv) < 2:
        print("Usage: python main.py <file_path>")
        return

    file_path = sys.argv[1]

    # Extract and normalize the file extension from the filename
    declared_extension = Path(file_path).suffix[1:].lower()
    
    # Open the aliases file
    try:
        with open('extension_aliases.json', 'r') as aliases_file:
            aliases = json.load(aliases_file)
    except FileNotFoundError:
        print("Error: Aliases file not found")
        return
    except json.JSONDecodeError:
        print("Error: Aliases file corrupted")
        return
    
    # Check for aliases
    normalized_extension = normalize_extension(declared_extension, aliases)

    # Collect file signatures from json and parse 
    try:
        with open('file_signatures.json', 'r') as signature_file:
            file_signatures = json.load(signature_file)
    except FileNotFoundError:
        print("Signatures file not found")
        return
    except json.JSONDecodeError:
        print("Error: Signatures file corrupted")
        return
    
    # Get length of file_signatures and the max value
    signature_lengths = get_signature_lengths(file_signatures)
    max_length = max(signature_lengths)
    
    # Get the header bytes of the original file
    header_bytes = get_file_signature(file_path, max_length)
    if header_bytes is None: return

    # Identify the actual file type by matching against known signatures
    detected_type = identify_file_type(header_bytes, signature_lengths, file_signatures)

    # Compare the declared extension with the detected file type
    if detected_type is not None:
        if detected_type == normalized_extension:
            print(f"{declared_extension} == {detected_type}")
            print("Extensions match.")
        else:
            print(f"{declared_extension} != {detected_type}")
            print("Mismatching file extensions. Potential file upload vulnerability.")


if __name__ == '__main__':
    main()

# TODO:
# 1. Handle files with no extension — currently Path.suffix returns '' which breaks the comparison
# 2. Add text-based format detection (source code, JSON, CSV, YAML, HTML) — magic bytes don't work for these
# 3. Improve output — report *why* a mismatch occurred (e.g. ZIP container, weak signature)
# 4. Add batch processing — accept a directory path and scan all files within it