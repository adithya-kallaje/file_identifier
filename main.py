import sys
import json
from pathlib import Path

# Maps common alternative extensions to their canonical form
EXTENSION_ALIASES = {
    # Images
    'jpg': 'jpeg',
    'jpe': 'jpeg',
    'jif': 'jpeg',
    'jfif': 'jpeg',
    'tif': 'tiff',
    'heic': 'heif',

    # Audio/Video
    'mpg': 'mpeg',
    'mpe': 'mpeg',
    'm1v': 'mpeg',
    'm2v': 'mpeg',
    'm4a': 'mp4',
    'm4v': 'mp4',
    'mid': 'midi',
    'ra': 'ram',

    # Documents & Web
    'htm': 'html',
    'markdown': 'md',
    'text': 'txt',

    # Archives
    'tgz': 'tar.gz',
    'tbz2': 'tar.bz2',
    '7z': '7zip',
    'lzma': 'xz',
}


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


def normalize_extension(extension: str) -> str:
    """Resolve an extension to its canonical form using the alias table."""
    return EXTENSION_ALIASES.get(extension, extension)


def main():
    # Ensure a file path was provided
    if len(sys.argv) < 2:
        print("Usage: python main.py <file_path>")
        return

    file_path = sys.argv[1]

    # Extract and normalize the file extension from the filename
    declared_extension = Path(file_path).suffix[1:].lower()
    normalized_extension = normalize_extension(declared_extension)

    # Read the first 20 bytes (enough to cover the longest known signature)
    try:
        with open(file_path, 'rb') as f:
            header_bytes = f.read(20)
    except FileNotFoundError:
        print("Error: File not found.")
        return
    except PermissionError:
        print("Error: Permission denied.")
        return
    
    # Collect file signatures from json and parse 
    with open('file_signatures.json', 'r') as signature_file:
        file_signatures = json.load(signature_file)

    # Identify the actual file type by matching against known signatures
    signature_lengths = get_signature_lengths(file_signatures)
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
# 1. Add more magic numbers (e.g. MP3, GIF, BMP, DOCX)