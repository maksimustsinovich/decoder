import json
import sys
import crc8
import re
import argparse


def print_log(timestamp, time_offset_us, format_string, args, specifiers):
    timestamp_string = "%010u.%06u" % (timestamp, time_offset_us)
    arg_index = 0
    specifier_index = 0
    log_message = format_string

    while arg_index < len(args) and specifier_index < len(specifiers):
        value = 0

        if "X" in specifiers[specifier_index]:
            value = hex(args[arg_index]).upper()

        if "x" in specifiers[specifier_index]:
            value = hex(args[arg_index])

        if "lld" in specifiers[specifier_index] or "llu" in specifiers[specifier_index] or \
                "u" in specifiers[specifier_index] or "d" in specifiers[specifier_index] or \
                "s" in specifiers[specifier_index]:
            value = str(args[arg_index])

        if "c" in specifiers[specifier_index]:
            value = str(chr(args[arg_index]))

        log_message = log_message.replace("%" + specifiers[specifier_index], value, 1)
        arg_index += 1
        specifier_index += 1

    print(timestamp_string, log_message)


def calculate_checksum(byte_array):
    return int(crc8.crc8(byte_array).hexdigest(), 16)


def le_uint_from_bytes(byte_array):
    return int.from_bytes(byte_array, "little", signed=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('binary')
    parser.add_argument('-m', "--json", required=True)

    args = parser.parse_args()

    json_path = args.json
    binary_path = args.binary

    with open(json_path, "r") as json_file:  # open a .json-file
        data_format = json.load(json_file)  # load their content
        data_format = {int(key): value for key, value in data_format.items()}  # transform dict so that key is number

    with open(binary_path, "rb") as binary_file:  # open a binary file
        while page := binary_file.read(512):  # read page
            offset = 0
            time_offset_us = 0
            timestamp = 0

            while offset < 512:
                entry = page[offset:offset + 10]  # get fixed payload

                checksum = le_uint_from_bytes(entry[:1])  # 1 byte is real CRC8 checksum
                size = le_uint_from_bytes(entry[1:2])  # 2 byte is size
                string_addr = le_uint_from_bytes(entry[2:6])  # 3-6 bytes is string addr

                entry = page[offset:offset + size]  # get full payload
                expected_checksum = calculate_checksum(entry[1:])

                if size < 10:  # if size less than fixed size - page ended
                    break

                if checksum != expected_checksum:  # checksum cannot be different
                    print(f"Error: invalid checksum at {binary_file.tell() - 512 + offset}", file=sys.stderr)
                    break

                if string_addr == 0:  # SyncFrame string address is always 0
                    timestamp = le_uint_from_bytes(entry[6:10])  # 7-10 bytes of SyncFrame is UNIX time

                    if size != 10:  # SyncFrame size is always 10
                        print(f"Error: invalid SyncFrame size at {binary_file.tell() - 512 + offset}", file=sys.stderr)
                        break

                else:  # else is Message
                    time_offset_us = le_uint_from_bytes(entry[6:10])  # 7-10 bytes of Message is time offset

                    format_string = data_format.get(string_addr)

                    if not format_string:  # if string with this address not exists
                        print(
                            f"""Error: unknown format string at address {string_addr}
                             at {binary_file.tell() - 512 + offset}""",
                            file=sys.stderr)

                    data = entry[10:size]  # get data
                    specifiers = re.findall(r"%(s|\d*[xXudc]|\d*llu|\d*lld)", format_string)  # get specifiers

                    args = []
                    data_index = 0
                    specifier_index = 0
                    while data_index < len(data):  # form args list by specifiers
                        if "X" in specifiers[specifier_index] or "x" in specifiers[specifier_index] or \
                                "u" in specifiers[specifier_index] or "d" in specifiers[specifier_index]:
                            args.append(le_uint_from_bytes(data[data_index:data_index + 4]))
                            data_index += 4

                        if "s" in specifiers[specifier_index]:
                            args.append(data_format.get(le_uint_from_bytes(data[data_index:data_index + 4])))
                            data_index += 4

                        if "lld" in specifiers[specifier_index] or "llu" in specifiers[specifier_index]:
                            args.append(le_uint_from_bytes(data[data_index:data_index + 8]))
                            data_index += 8

                        if "c" in specifiers[specifier_index]:
                            args.append(data[data_index])
                            data_index += 1

                        specifier_index += 1

                    print_log(timestamp, time_offset_us, format_string, args, specifiers)

                offset += size  # increment offset
