import json
import csv
from html.parser import HTMLParser
import xml.etree.ElementTree as ET


def check_readability(data:bytes) -> str | None:
    '''Check for readability'''
    decoded_data = ''
    try:
        decoded_data = data.decode()
        return decoded_data
    except UnicodeDecodeError:
        return None


def check_json(data:str) -> str | None:
    '''Check for json format'''
    decoder = json.JSONDecoder()
    try:
        decoded_file = decoder.decode(data)
        if isinstance(decoded_file, (dict,list)):
            return 'json'
        else: return None  
    except json.JSONDecodeError:
        return None


def check_csv(data:str) -> str | None:
    '''Check for csv format'''
    try:
        sniffer = csv.Sniffer()
        dialect = sniffer.sniff(data, delimiters=',;\t|')
        
        csv_reader = csv.reader(data.splitlines(), dialect)
        rows = list(csv_reader)
        
        if len(rows) < 3:
            return None
        
        # Check if all rows have consistent column count
        col_count = len(rows[0])
        if col_count < 2:
            return None
            
        for row in rows[1:]:
            if len(row) == 0: continue
            if len(row) != col_count:
                return None
        
        return 'csv'
    except csv.Error:
        return None
    
    
def check_html(data:str) -> str | None:
    '''Check for html format'''
    try:
        class MyHTMLParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.found_html = False

            def handle_starttag(self, tag, attrs):
                if tag == 'html':
                    self.found_html = True

        parser = MyHTMLParser()
        parser.feed(data)
        if parser.found_html: return 'html'
        return None
    except Exception:
        return None
    
    
def check_xml(data:str) -> str | None:
    '''Check for XML'''
    try:
        root = ET.fromstring(data)
        # print(f"XML root value -> {root.tag}")

        # Extract namespace URI from root tag
        ns_uri = None
        if '}' in root.tag:
            ns_uri = root.tag.split('}')[0][1:]
            
        # print(f"Namespace URI: {ns_uri}")

        # Identify file type by namespace URI or tag name
        if ns_uri:
            if 'kml' in ns_uri.lower():
                return 'kml'
            elif 'svg' in ns_uri.lower():
                return 'svg'
            else:
                return 'xml'
        else:
            tag_name = root.tag.lower()
            if 'kml' in tag_name:
                return 'kml'
            elif 'svg' in tag_name:
                return 'svg'
            else:
                return 'xml'
    except ET.ParseError:
        return None


def text_based_format_detection(file_path:str, current_extension: str, header_bytes: bytes) -> str | None:
    
    with open(file_path, 'rb') as f:
        f.seek(len(header_bytes))
        rest = f.read()
        data = header_bytes + rest
    
    decoded_data = check_readability(data)
    if decoded_data == None: return current_extension
    
    is_json = check_json(decoded_data)
    if is_json is not None: return is_json
    
    is_csv = check_csv(decoded_data)
    if is_csv is not None: return is_csv
    
    is_html = check_html(decoded_data)
    if is_html is not None: return is_html
    
    is_xml = check_xml(decoded_data)
    if is_xml is not None: return is_xml
    
    if current_extension == None: return "txt"
    return current_extension
