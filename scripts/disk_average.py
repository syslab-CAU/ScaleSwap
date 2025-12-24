import argparse
import re
import json


parser = argparse.ArgumentParser(description="'dstat' average calculator", add_help=False)
parser.add_argument("filename", type=argparse.FileType('r'))
parser.add_argument("-h", "--human-readable", action='store_true', help="print sizes like 1K 234M 2G etc.")
parser.add_argument("--help", required=False, action='store_true', help="display this help and exit")


def get_num(bytes_str):
    mul_val = 1
    if "k" in bytes_str:
        mul_val = 1000
    elif "M" in bytes_str:
        mul_val = 1000 * 1000
    return int(re.sub(r'[^0-9]', '', bytes_str)) * mul_val



def get_split_element(line):
    bytes = []
    tmp = line.strip().split("|")
    for e in tmp:
        bytes.extend(e.split())

    ret = []
    for byte in bytes:
        ret.append(get_num(byte))
    return ret


def byte_transform(bytes, bsize=1000):
    to = ["bytes", "KB", "MB", "GB", "TB", "PB"]
    cnt = 0
    while (bytes >= bsize):
        bytes /= bsize
        cnt += 1
    return str(round(bytes, 2)) + " " + to[cnt]


def get_average(file, human_readable):
    start_cal = False
    header_list = []
    
    cnt = 0
    total_list = []
    for line in file.readlines():
        if start_cal == False:
            if "read" in line:
                start_cal = True
                header = line.strip().split("|")
                for e in header:
                    header_list.extend(e.split())
                    total_list = [0] * len(header_list)
            continue

        element_list = get_split_element(line)
        cnt += 1
        total_list = [x + y for x, y in zip(total_list, element_list)]

    ret = {}
    except_headers = ["usr", "sys", "idl", "wai", "stl"]
    for i in range(len(header_list)):
        if header_list[i] in except_headers:
            continue

        if human_readable:
            ret[header_list[i]] = byte_transform(total_list[i] / cnt)
        else:
            ret[header_list[i]] = str(total_list[i] / cnt)

    return ret


if __name__ == "__main__":
    args = parser.parse_args()
    if args.help:
        parser.print_help()
        exit()
    print(args)
    
    ret = get_average(args.filename, args.human_readable)
    
    print(json.dumps(ret, indent=2, ensure_ascii=False))
