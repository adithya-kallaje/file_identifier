import sys
from pathlib import Path

magic_numbers = {
    b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a': 'png',
    b'\x25\x50\x44\x46\x2d': 'pdf',
    b'\x50\x4b\x03\x04': 'zip',
    b'\xff\xd8\xff\xe0': 'jpeg',
    b'\x7f\x45\x4c\x46': 'elf'
}

# Returns the possible signature lengths
def gen_sign_length(magic_numbers):
    file_sign_lengths = set()

    for signatures in magic_numbers:
        file_sign_lengths.add(len(signatures))
    
    return file_sign_lengths

# Returns the file type    
def check_file_signature(data, file_sign_lengths, magic_numbers):
    for i in sorted(file_sign_lengths, reverse=True):
        file_sign = data[0:i]
        # print(file_sign)
        
        if file_sign in magic_numbers: 
            print(magic_numbers[file_sign])
            return magic_numbers[file_sign]

    print("Unable to identify file")
    return None

# Main function
def main():
    if(len(sys.argv) < 2):
        print("Please enter the file address")
        return
    
    filename = sys.argv[1]
    file_extension_original = Path(filename).suffix[1:]
    
    try:
        with open(filename, 'rb') as f:
            data = f.read(20)
            # print(data.hex())
            
        print("Original extension:", file_extension_original)
    
    except FileNotFoundError:
        print("File not found")
        return
    
    except PermissionError:
        print("You dont have permission to access this file")
        return

    file_sign_lengths = gen_sign_length(magic_numbers)
    file_extension_actual = check_file_signature(data, file_sign_lengths, magic_numbers)
    
    if file_extension_actual is not None and file_extension_actual != file_extension_original:
        print("Mistmatching file extensions. Potential file upload vulnerability")
    

main()

# TODO:
# 1. Check for mistmatches even if filetype is same (eg: jpg and jpeg)
# 2. Add more magic numbers (e.g. MP3, GIF, BMP, DOCX)