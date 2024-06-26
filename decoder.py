import json
import sys
import crc8
import re
import argparse
import struct

ENTRY_FIXED_SIZE = 10
PAGE_SIZE = 512


def find_first_number_sequence(s):
    match = re.search(r'\d+', s)
    if match:
        return match.group()
    return None


def generate_log_message(time, time_offset, fmt_string, arguments, fmt_specifiers):
    """Generate log message with C-like string format"""

    timestamp_string = "%010u.%06u" % (time, time_offset)
    arg_index = 0
    fmt_index = 0
    log_message = fmt_string

    while arg_index < len(arguments) and fmt_index < len(fmt_specifiers):
        value = 0

        current_specifier = fmt_specifiers[fmt_index]
        current_argument = arguments[arg_index]

        # Parse format specifier
        align = ''
        fill_char = ' '

        number_sequence = find_first_number_sequence(current_specifier)

        width = 0 if number_sequence is None else int(number_sequence)

        if current_specifier.startswith("-"):
            align = "-"

        elif current_specifier.startswith("0"):
            fill_char = "0"

        if "X" in current_specifier:
            value = hex(current_argument).upper().removeprefix("0X")
        elif "x" in current_specifier:
            value = hex(current_argument).removeprefix("0x")
        elif ("lld" in current_specifier or "llu" in current_specifier or
              "u" in current_specifier or "d" in current_specifier or "s" in current_specifier):
            value = str(current_argument)
        elif "c" in current_specifier:
            value = str(chr(current_argument))

        if width > 0:
            if align == '-':
                value = value.ljust(width, fill_char)
            else:
                value = value.rjust(width, fill_char)

        log_message = log_message.replace("%" + current_specifier, value, 1)
        arg_index += 1
        fmt_index += 1

    return f"{timestamp_string} {log_message}"


def calculate_checksum(byte_array):
    """Calculates CRC8 checksum for byte array"""

    return int(crc8.crc8(byte_array).hexdigest(), 16)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('binary')
    parser.add_argument('-m', "--json", required=True)

    args = parser.parse_args()  # parse CLI arguments

    json_path = args.json
    binary_path = args.binary

    with open(json_path, "r") as json_file:  # open a .json-file
        data_format = json.load(json_file)  # load their content
        data_format = {int(key): value for key, value in data_format.items()}  # transform dict so that key is number

    with (open(binary_path, "rb") as binary_file):  # open a binary file
        while page := binary_file.read(PAGE_SIZE):  # read page
            offset = 0
            time_offset_us = 0
            timestamp = 0

            while offset < PAGE_SIZE:
                entry = page[offset:offset + ENTRY_FIXED_SIZE]  # get fixed payload

                checksum, size, string_addr, time_value = struct.unpack("<BBII", entry)

                entry = page[offset:offset + size]  # get full payload
                expected_checksum = calculate_checksum(entry[1:])

                if size < ENTRY_FIXED_SIZE:  # if size less than fixed size - page ended
                    break

                if checksum != expected_checksum:  # checksum cannot be different
                    print(f"Error: invalid checksum at {binary_file.tell() - PAGE_SIZE + offset}", file=sys.stderr)
                    break

                if string_addr == 0:  # SyncFrame string address is always 0
                    timestamp = time_value

                    if size != ENTRY_FIXED_SIZE:  # SyncFrame size is always 10
                        print(f"Error: invalid SyncFrame size at {binary_file.tell() - PAGE_SIZE + offset}",
                              file=sys.stderr)
                        break

                else:  # else is Message
                    time_offset_us = time_value

                    format_string = data_format.get(string_addr)

                    if not format_string:  # if string with this address not exists
                        print(
                            f"""Error: unknown format string at address {string_addr}
                             at {binary_file.tell() - PAGE_SIZE + offset}""",
                            file=sys.stderr)

                    data = entry[ENTRY_FIXED_SIZE:size]  # get data
                    specifiers = re.findall(r"%(-?\d*[sxXudc]|\d*llu|\d*lld)", format_string)  # get specifiers

                    args = []
                    data_index = 0
                    specifier_index = 0
                    while data_index < len(data):  # form args list by specifiers
                        specifier = specifiers[specifier_index]
                        if "d" in specifier:  # signed decimal
                            value = struct.unpack("<i", data[data_index:data_index + 4])
                            args.append(*value)
                            data_index += 4

                        elif ("u" in specifier or "X" in specifier or
                              "x" in specifier):  # unsigned decimal or upper / lower hex
                            value = struct.unpack("<I", data[data_index:data_index + 4])
                            args.append(*value)
                            data_index += 4

                        elif "s" in specifier:  # string
                            value = struct.unpack("<I", data[data_index:data_index + 4])
                            args.append(data_format.get(*value))
                            data_index += 4

                        elif "lld" in specifier:  # long long signed decimal
                            value = struct.unpack("<q", data[data_index:data_index + 8])
                            args.append(value)
                            data_index += 8

                        elif "llu" in specifier:  # long long unsigned decimal
                            value = struct.unpack("<Q", data[data_index:data_index + 8])
                            args.append(value)
                            data_index += 8

                        elif "c" in specifier:  # char
                            args.append(data[data_index])
                            data_index += 1

                        specifier_index += 1

                    print(generate_log_message(timestamp, time_offset_us, format_string, args, specifiers))

                offset += size  # increment offset
