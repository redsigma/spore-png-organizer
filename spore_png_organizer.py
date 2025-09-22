####################################################################################################################################################
# This script will organize spore png files contained in a folder into the folder structure needed by the `My Spore Creations` folder
# 
# Parts of the code were taken from the following repos:
# https://github.com/Spore-Community/PNG-Decoder-Python/blob/fd5593964180fbf6e0dc5bb442f54351fda08b68/spore_decoder_by_ymgve_and_rick.py#L17
# https://github.com/Spore-Community/PNG-Decoder-NetCore/blob/8d67a66338ad2d8f0538ddc8ed4c8f68d88a325b/Program.cs#L144
#
####################################################################################################################################################


###############################################################################
def get_current_script_path():
    from pathlib import Path
    
    current_script_dir = Path(__file__).resolve().parent
    return current_script_dir


###############################################################################
def parse_command_line_arguments():
    import argparse
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--source_directory', help='source folder to scan for images', required=True)
    parser.add_argument('-o', '--target_directory', default=get_current_script_path(), help='target folder where to save the organized spore folder structure')
    parser.add_argument('-d', '--dump_xml', help='save decoded png output to file', action='store_true')
    parser.add_argument('-s', '--skip_file_copy', help='do not copy file to target_directory', action='store_true')
    parser.add_argument('-dh', '--dump_header_as_json', help='only save decoded png header to file', action='store_true')
    parser.add_argument('-r', '--replace_existing_files', help='overwrite files that already exist', action='store_true')

    args = parser.parse_args()
    return args


###############################################################################
def read_header(data):
    """
    Header format:
        #    contents   name        description
        1    "spore"
        2    %04d	    version     version? appears to always be 5
        3    %08x	    tid         type id (0x2b978c46 means extracted xml)
        4    %08x	    gid         group id  (0x40626200 is the default package)
        5    %08x	    id          instance id
        6    %08x	    mid         machine id? (constant for a user)
        7    %016x	    cid         creature id ((int64)(-1) if offline)
        8    %016x	    time        timestamp in seconds since AD 1 (?)
        9    %02x	                 length of user name
        10   string	    uname       user name
        11   %016llx	uid         user id
        12   %02x	                 length of creature name
        13   string	    name        creature name
        14   %03x	                 length of creature description
        15   string	    desc        creature description
        16   %02x	                 length of creature tags
        17   string	    tags        creature tags
        18   %02x	                 count of following %08x (unused?)
        19   %08x	    trail       repeats for previous count
    """
    def peek(n):
        return ret[0][:n]

    def pop(n):
        d = peek(n)
        ret[0] = ret[0][n:]
        ret["meta_raw"] += d
        return d
    
    def pop_hex_as_int(width):
        return int(pop(width), 16)

    def pop_int(name, width):
        ret["meta"][name] = pop_hex_as_int(width)
        
    def pop_str(name: str, width: int):
        n_bytes = pop_hex_as_int(width)
        if len(ret[0]) < n_bytes:
            return
        ret["meta"][name] = pop(n_bytes).decode("utf-8")

    def pop_trail():
        if len(ret[0]) < 2:
            return
        
        try:
            int(peek(2), 16)
        except:
            # skip if ending has only partial multibyte characters
            return

        count = pop_hex_as_int(2)
        trails = [pop_hex_as_int(8) for _ in range(count)]
        ret["meta"]["trail"] = trails

    ret = {0: data, "meta":{}, "meta_raw": b''}
 
    if not pop(5) == b'spore':
        raise ValueError

    pop_int('version', 4)
    pop_int('tid',     8)
    pop_int('gid',     8)
    pop_int('id',      8)
    pop_int('mid',     8)
    pop_int('cid',    16)
    pop_int('time',   16)

    # Adding the parent
    if ret["meta"]['version'] == 6:
        pop_int('parent',16)

    pop_str('uname',   2)
    pop_int('uid',    16)

    pop_str('name',    2)
    pop_str('desc',    3)
    pop_str('tags',    2)

    pop_trail()

    return {"xml": ret[0], "meta": ret["meta"], "meta_raw": ret["meta_raw"]}


###############################################################################
class Decoder(object):
    def __init__(self, data):
        self.data = data
        self.hash = 0x811c9dc5
        self.next_pos = 0x0b400

    def __iter__(self):
        return self

    def __next__(self):
            byte = 0
            for i in range(8):
                n = self.next_pos
                d = self.data[n]
                e = (self.hash * 0x1000193) & 0xffffffff
                self.hash = e ^ ((n & 7) | (d & 0xf8))
                e = ((d&1) << 7) ^ ((self.hash & 0x8000) >> 8)
                byte = (byte >> 1) | e
                self.next_pos = (n >> 1) ^ (0x0b400 & -(n & 1))
                    
                if (self.next_pos == 0x0b400):
                    raise StopIteration

            return byte
    
    def decode(self, dst):
        for j in range(len(dst)):
            b = 0
            for i in range(8):
                n = self.next_pos
                d = self.data[n]
                e = (self.hash * 0x1000193) & 0xffffffff
                self.hash = e ^ ((n & 7) | (d & 0xf8))
                e = ((d & 1) << 7) ^ ((self.hash & 0x8000) >> 8)
                b = (b >> 1) | e
                self.next_pos = (n >> 1) ^ (0x0b400 & -(n & 1))

                if self.next_pos == 0x0b400:
                    return j

            dst[j] = b

        return len(dst)

    def get_data(self):
        byte_chars = [chr(x).encode('latin-1') for x in self]
        bytes_string = b''.join(byte_chars)
        return bytes_string


###############################################################################
def read_int32(stream):
    import struct
    data = stream.read(4)
    data_reversed = data[::-1]
    return struct.unpack('<i', data_reversed)[0]


###############################################################################
def get_extra_data(path):
    import os
    
    with open(path, 'rb') as stream:
        # Skip magic
        stream.seek(8, os.SEEK_SET)

        type_code = 0
        while type_code != 0x49454E44:
            length = read_int32(stream)
            type_code = read_int32(stream)
            
            stream.seek(length, os.SEEK_CUR)
            _ = read_int32(stream)

        has_extra_data = stream.tell() != os.path.getsize(path)
        if has_extra_data:
            length = read_int32(stream) 
            type_code = read_int32(stream)
            if type_code == 0x73704F72:
                data = stream.read(length)
                return data
        return None


###############################################################################
def get_image_data(file):
    from PIL import Image
    import sys

    if file == None:
        print("warning: no file to decode")
        return

    im = Image.open(file if file != '-' else sys.stdin)
    im.load()
    
    if im.size != (128, 128):
        print("error: image size is not 128x128")

    image_data = []
    for y in range(128):
        for x in range(128):
            (r,g,b,a) = im.getpixel((x,y))
            image_data.extend((b,g,r,a))
    
    return image_data


###############################################################################
def decode_creature(file):
    image_data = get_image_data(file)
    if not image_data:
        return

    creature_data = {}
    extra = get_extra_data(file)
  
    if extra:
        creature_data = decode_creature_with_extra_data_helper(extra, image_data)
    else:
        creature_data = decode_creature_helper(image_data)

    return creature_data


###############################################################################
def decode_data(data):
    import zlib
    HEADER_SIZE = 8

    decompressed_data = b''
    try:
        is_data_incomplete = False

        decompressor = zlib.decompressobj()
        decompressed_data = decompressor.decompress(data[HEADER_SIZE:]) + decompressor.flush()

    except zlib.error as err:
        is_data_incomplete = True
        decompressed_data = b''
        
    return is_data_incomplete, decompressed_data


###############################################################################
def decode_creature_helper(image_data):
    stream = Decoder(image_data)
    data = stream.get_data()

    is_incomplete, decompressed_data = decode_data(data)

    creature_data = read_header(decompressed_data)
    creature_data["incomplete"] = is_incomplete
    
    return creature_data


###############################################################################
def decode_creature_with_extra_data_helper(extra, image_data):
    import struct

    stream = Decoder(image_data)
    length_data = bytearray(8)
    stream.decode(length_data)
    
    length = struct.unpack("<i", length_data[4:len(length_data)])[0]
    if (length < 0):
        length = -length
    
    is_incomplete, decompressed_data = decode_data(extra, length)
    creature_data = read_header(decompressed_data)
    creature_data["incomplete"] = is_incomplete
    
    return creature_data


###############################################################################
def has_all_tags(xml_binary_data, xml_tags : dict):
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_binary_data)
    for tag in xml_tags:
        
        has_tag = root.find(f".//{tag}") != None
        if not has_tag:
            return False
    return True


###############################################################################
def is_image_cell(creature_metadata):
    creature_type_id = creature_metadata["tid"]
    types = [1033349348]
    if creature_type_id in types:
        return True
    
    return False


###############################################################################
def is_image_creature(creature_metadata):
    creature_type_id = creature_metadata["tid"]
    types = [731352134]
    if creature_type_id in types:
        return True
    
    return False


###############################################################################
def is_image_vehicle(creature_metadata):
    creature_type_id = creature_metadata["tid"]
    types = [610804372]
    if creature_type_id in types:
        return True
    
    return False


###############################################################################
def is_image_spaceship(creature_metadata):
    creature_type_id = creature_metadata["tid"]
    types = [1198168263]
    if creature_type_id in types:
        return True
    
    return False
        

###############################################################################
def is_image_building(creature_metadata):
    creature_type_id = creature_metadata["tid"]
    types = [597278293]
    if creature_type_id in types:
        return True
    
    return False


###############################################################################
def is_image_adventure(creature_metadata):
    creature_type_id = creature_metadata["tid"]
    types = [912954125]
    if creature_type_id in types:
        return True
    
    return False


###############################################################################
def open_file(file: str):
    from pathlib import Path
    path = Path(file)
    if not path.exists():
        print(f"error: file {file} doesnt exist")
        return
    
    return str(path.absolute())


###############################################################################
def create_if_not_exist(folder_name: str, folder_path: str, is_data_incomplete: bool = False):
    script_path = get_current_script_path()
    
    output_path = script_path 
    if folder_path:
        output_path = folder_path
        
    output_path = output_path / "spore_creations" 
    if is_data_incomplete:
        # incomplete png files are stored in a separate folder 
        # - adding these creatures via `My Spore Creations` or drag n drop might crash the game
        output_path = output_path / "INCOMPLETE"
    
    output_path = output_path / folder_name
  
    output_path.mkdir(parents=True, exist_ok=True)
    return output_path.absolute()


###############################################################################
def add_to_folder(output_filename: str, output_path: str, source_file_path: str):
    from pathlib import Path
    from shutil import copy

    src_path_creature_image = Path(source_file_path)
    if not src_path_creature_image.exists():
        return
    
    path = Path(output_path)
    dest_path_creature_image = path / output_filename
    dest_path_creature_image = dest_path_creature_image.with_suffix(".png")
     
    if not args.replace_existing_files and dest_path_creature_image.exists():
        return

    copy(src_path_creature_image, dest_path_creature_image)


###############################################################################
def dump_xml_to_folder(output_filename: str, output_path: str, content_to_dump: str):
    from pathlib import Path

    path = Path(output_path)
    dest_path_creature_image = path / output_filename
    dest_path_creature_image = dest_path_creature_image.with_suffix(".xml")
    
    if not args.replace_existing_files and dest_path_creature_image.exists():
        return
    
    if content_to_dump:
        dest_path_creature_image.write_bytes(content_to_dump)
        return


###############################################################################
def dump_json_header_to_folder(output_filename: str, output_path: str, content_to_dump: str):
    from pathlib import Path

    path = Path(output_path)
    dest_path_creature_image = path / output_filename
    dest_path_creature_image = dest_path_creature_image.with_suffix(".json")
    
    if not args.replace_existing_files and dest_path_creature_image.exists():
        return
    
    if content_to_dump:
        dest_path_creature_image.write_bytes(content_to_dump)
        return


###############################################################################
def add_to_folder_structure(creature_content: dict, file_path: str):
    data_not_parsed = not creature_content
    if data_not_parsed:
        destination_filename = make_output_filename(creature_content)
        destination_path = make_output_destination("UNKNOWN")
        add_to_folder(destination_filename, destination_path, file_path)
        return

    metadata = creature_content["meta"]
    
    if is_image_creature(metadata):
        save_creature("Creatures", file_path, creature_content)
        
    elif is_image_vehicle(metadata):
        save_creature("Vehicles", file_path, creature_content)
        
    elif is_image_spaceship(metadata):
        save_creature("UFOs", file_path, creature_content)
        
    elif is_image_building(metadata):
        save_creature("Buildings", file_path, creature_content)
    
    elif is_image_adventure(metadata):
        save_creature("Adventures", file_path, creature_content)
        
    elif is_image_cell(metadata):
        save_creature("Cells", file_path, creature_content)
        
    else:
        save_creature("OTHER", file_path, creature_content)


###############################################################################
def make_output_filename(creature_content: dict):
    author = creature_content["meta"]["uname"]
    creature_name = creature_content["meta"]["name"]
    output_filename = f"{author}_{creature_name}"
    return output_filename


###############################################################################
def make_output_destination(folder_name : str, has_incomplete_data: bool = False):
    from pathlib import Path
    
    output_path = ""
    if args.target_directory:
        output_path = Path(args.target_directory)
        
    destination_path = create_if_not_exist(folder_name, output_path, has_incomplete_data)
    return destination_path
    

###############################################################################
def save_creature(folder_name: str, source_file_path: str, creature_content: dict):
    xml_content = creature_content["xml"]
    
    metadata = creature_content["meta_raw"].decode('utf-8')
    xml_content = bytes(f'{metadata}{xml_content}', encoding='utf-8')
     
    has_incomplete_data = creature_content["incomplete"]

    destination_filename = make_output_filename(creature_content)
    destination_path = make_output_destination(folder_name, has_incomplete_data)

    if args.dump_header_as_json:
        json_wannabe_content = bytes(str(creature_content["meta"]), encoding='utf-8')
        dump_json_header_to_folder(destination_filename, destination_path, json_wannabe_content)  

    if args.dump_xml:
        dump_xml_to_folder(destination_filename, destination_path, xml_content)

    if args.skip_file_copy:
        return
    
    add_to_folder(destination_filename, destination_path, source_file_path)


###############################################################################
def copy_files_from_to(src_folder: str, dest_folder: str):
    from pathlib import Path
    
    path_source = Path(src_folder)
    path_destination = Path(dest_folder)
    
    if not path_source.exists():
        return
    
    if not path_destination.exists():
        return
    
    for file_path in path_source.glob('**/*.png'):
        if not file_path.exists():
            continue
        
        path = open_file(file_path)

        creature = decode_creature(path)
        
        add_to_folder_structure(creature, path)


args = parse_command_line_arguments()
copy_files_from_to(args.source_directory, args.target_directory)
