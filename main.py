import sys

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
            return

    print("Unable to identify file")

# Main function
def main():
    if(len(sys.argv) < 2):
        print("Please enter the file address")
        return
    
    filename = sys.argv[1]
    
    try:
        with open(filename, 'rb') as f:
            data = f.read(20)
            # print(data.hex())
            
    except FileNotFoundError:
        print("File not found")
        return
    
    except PermissionError:
        print("You dont have permission to access this file")
        return

    file_sign_lengths = gen_sign_length(magic_numbers)
    check_file_signature(data, file_sign_lengths, magic_numbers)

main()

# TODO:
# 1. Remove debug print(data.hex()) line
# 2. Add extension spoofing detection:
#    - Extract file extension from filename (os.path.splitext or pathlib.Path.suffix)
#    - Return detected type from check_file_signature instead of printing inside it
#    - Compare extension vs detected type and warn if mismatch
# 3. Add more magic numbers (e.g. MP3, GIF, BMP, DOCX)