import re


def inspect_magic_bytes(header_bytes: bytes, signatures_list: dict) -> str | None:
    '''Match file header bytes against known signatures; returns longest/most-specific match.'''
    detected_ext = None
    detected_ext_length = 0
    
    # Iterate through all file types
    for file_type in signatures_list:
        
        # Ignore json comments
        if file_type.startswith('__'): continue
        
        # A multi-condition entry is a list of variations (list-of-lists);
        # an ordinary entry is a flat list of signature dicts.
        elif isinstance(signatures_list[file_type][0], list):
            matched_length = inspect_multi_condition_signature(header_bytes=header_bytes, multi_signatures=signatures_list[file_type])
            
            if matched_length is not None and matched_length > detected_ext_length:
                detected_ext_length = matched_length
                detected_ext = file_type
        
        else:
            for signature_check in signatures_list[file_type]:
            
                header_offset = signature_check["offset"] * 2
                matching_signatures = '.' * header_offset + signature_check["signature"]
                
                if re.match(matching_signatures, header_bytes.hex()) and len(signature_check["signature"]) > detected_ext_length:
                    detected_ext = file_type
                    detected_ext_length = len(signature_check["signature"])
    
    return detected_ext


def inspect_multi_condition_signature(header_bytes: bytes, multi_signatures: list[list[object]]) -> int | None:
    '''Match file header bytes against all multiple bytes; returns the longest matched byte'''
    verdict = [False, 0]
    
    # Go through each variation
    for variation in multi_signatures:
        match = True
        
        # Go through all mappings for a variation, return false if even one is incorrect
        for signature_check in variation:
            header_offset = signature_check["offset"] * 2
            matching_signatures = '.' * header_offset + signature_check["signature"]
            
            if not re.match(matching_signatures, header_bytes.hex()): 
                match = False
                break
            
        if match:
            cur_length = 0
            for signature_check in variation: cur_length += len(signature_check["signature"])
            
            verdict[0] = True
            verdict[1] = max(verdict[1], cur_length)
    
    if verdict[0]: return verdict[1]
    else: return None                
