import sys
from pathlib import Path

# File signatures (magic numbers) mapped to their corresponding file types
FILE_SIGNATURES = {
    b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a': 'png',
    b'\x25\x50\x44\x46\x2d': 'pdf',
    b'\x50\x4b\x03\x04': 'zip',
    b'\xff\xd8\xff\xe0': 'jpeg',
    b'\x7f\x45\x4c\x46': 'elf',
}

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
    return {len(sig) for sig in signatures}


def identify_file_type(header_bytes: bytes, signature_lengths: set, signatures: dict) -> str | None:
    """Match the file header against known signatures, trying longest matches first."""
    for length in sorted(signature_lengths, reverse=True):
        candidate = header_bytes[:length]
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

    # Identify the actual file type by matching against known signatures
    signature_lengths = get_signature_lengths(FILE_SIGNATURES)
    detected_type = identify_file_type(header_bytes, signature_lengths, FILE_SIGNATURES)

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