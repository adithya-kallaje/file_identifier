import sys
import json
import csv
from html.parser import HTMLParser
import xml.etree.ElementTree as ET

def text_based_format_detection(data:bytes) -> str | None:
        decoded_data = ''
        
        '''Check for readability'''
        try:
            decoded_data = data.decode()
        except UnicodeDecodeError:
            print("Unable to identify file type from signature")
            return None
        
        '''Check for json format'''
        decoder = json.JSONDecoder()
        try:
            decoded_file = decoder.decode(decoded_data)
            return 'JSON'
        except json.JSONDecodeError:
            pass
        
        
        '''Check for csv format'''
        try:
            is_csv = True
            # Generate the csv sniffer and reader
            sniffer = csv.Sniffer()
            dialect = sniffer.sniff(decoded_data)
            
            csv_reader = csv.reader(decoded_data.splitlines(), dialect)

            # Number of columns in header
            no_of_cols = 0

            for row in csv_reader:
                no_of_cols = len(row)
                if no_of_cols < 2:
                    is_csv = False    
                break
            
            # Check if number of columns stay consistent 
            for row in csv_reader:
                if len(row) == 0: pass
                elif no_of_cols != len(row): 
                    is_csv = False
                    break
            
            if is_csv: return 'CSV'
        except csv.Error:
            pass
            
            
        '''Check for html format'''
        try:
            class MyHTMLParser(HTMLParser):
                def __init__(self):
                    super().__init__()
                    self.found_html = False

                def handle_starttag(self, tag, attrs):
                    if 'html' in tag:
                        self.found_html = True

            parser = MyHTMLParser()
            parser.feed(decoded_data)
            if parser.found_html: return 'HTML'
        except:
            pass
            
            
        '''Check for XML'''
        try:
            root = ET.fromstring(decoded_data)
            # print(f"XML root value -> {root.tag}")

            # Extract namespace URI from root tag
            ns_uri = None
            if '}' in root.tag:
                ns_uri = root.tag.split('}')[0][1:]
                
            # print(f"Namespace URI: {ns_uri}")

            # Identify file type by namespace URI or tag name
            if ns_uri:
                if 'kml' in ns_uri.lower():
                    return 'KML'
                elif 'svg' in ns_uri.lower():
                    return 'SVG'
                else:
                    return 'XML'
            else:
                tag_name = root.tag.lower()
                if 'kml' in tag_name:
                    return 'KML'
                elif 'svg' in tag_name:
                    return 'SVG'
                else:
                    return 'XML'
        except ET.ParseError:
            pass
            
            
        '''Check for YAML'''
        try:
            lines = decoded_data.split('\n')
            indicators = set()
            
            # Check for common YAML patterns
            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                
                # Key-value pairs with colons
                if ':' in stripped and not stripped.startswith('[') and not stripped.startswith('{'):
                    indicators.add(1)
                
                # List items starting with dash
                if stripped.startswith('- '):
                    indicators.add(2)
                
                # Nested indentation (YAML specific)
                if line and line[0] == ' ' and ':' in stripped:
                    indicators.add(3)
                
                # Boolean values
                if stripped.lower() in ('true', 'false', 'yes', 'no', 'on', 'off'):
                    indicators.add(4)
                
                # Null values
                if stripped.lower() in ('null', '~'):
                    indicators.add(5)
                
                # Anchors and aliases
                if stripped.startswith('&') or stripped.startswith('*'):
                    indicators.add(6)
                    
                if len(indicators) >= 3: break
                
            # print(f"Indicators for YAML = {indicators}")
            
            if len(indicators) >= 3: return 'YAML'
            # if len(indicators) >= 3: print('YAML')
        except Exception:
            pass
            
            
        '''Check for Markdown'''
        try:
            indicators = set()
            lines = decoded_data.split('\n')
            
            # Check for common Markdown patterns
            for line in lines:
                stripped = line.strip()
                
                # Headings with # symbols
                if stripped.startswith('#') and stripped.startswith('#' * len(stripped.split()[0])):
                    indicators.add(1)
                
                # Unordered lists with -, *, or +
                elif stripped.startswith(('- ', '* ', '+ ')):
                    indicators.add(5)
                
                else:
                    # Bold or italic markers
                    if '**' in stripped or '__' in stripped or '*' in stripped:
                        indicators.add(2)
                    
                    # Links [text](url)
                    if '[' in stripped and ']' in stripped and '(' in stripped:
                        indicators.add(3)
                    
                    # Code blocks with backticks
                    if '```' in stripped or stripped.startswith('    '):
                        indicators.add(4)
                    
                    # Ordered lists with numbers
                    if stripped and stripped[0].isdigit() and stripped[1:].startswith('. '):
                        indicators.add(6)
                    
                if len(indicators) >= 2: break
                    
            # print(f"Indicators for Markdown = {indicators}")
            
            if len(indicators) >= 2:
                return 'Markdown'
            else:
                return None
        except Exception as e:
            return None
                    

filepath = sys.argv[1]
# filepath = 'test_files/sample.md'
with open(filepath, 'rb') as f:
    data = f.read()
    file_type = text_based_format_detection(data)   
    
    if file_type is None: print("Dumb fucking file detected")
    else: print(f"Detected file type: {file_type}")
