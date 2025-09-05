#   Copyright Notice:
#   Copyright 2021-2022 DMTF. All rights reserved.
#   License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md

import os
import struct
import sys

# python version
python_version = sys.version_info[0]

def get_path():
    file_list = []
    for path in sys.argv[1:]:
        if not os.path.exists(path):
            continue
        if os.path.isfile(path):
            if check_file(path):
                file_list.append(path)
        else:
            subPathList = os.listdir(path)
            for i in range(0, len(subPathList)):
                subPath = os.path.join(path, subPathList[i])
                if os.path.isfile(subPath) and check_file(subPath):
                    file_list.append(subPath)
    if not file_list:
        print("The input is neither ktest format file nor folder that include ktest format file.\n")
        print_usage()
    return file_list

def check_file(file):
    k_test_file = open(file, 'rb')
    k_test_header = k_test_file.read(5)
    k_test_file.close()
    if k_test_header == b'KTEST' or k_test_header == b"BOUT\n":
        return True
    else:
        return False

def analyse_file(file):
    object_list = []
    k_test_file = open(file, 'rb')
    k_test_file.read(5)
    k_test_version = struct.unpack('>i', k_test_file.read(4))[0]
    target_num = struct.unpack('>i', k_test_file.read(4))[0]
    for i in range(target_num):
        k_test_file.read(struct.unpack('>i', k_test_file.read(4))[0])

    if k_test_version >= 2:
        k_test_file.read(8)

    object_num = struct.unpack('>i', k_test_file.read(4))
    for i in range(object_num):
        objectName = k_test_file.read(struct.unpack('>i', k_test_file.read(4))[0])
        objectData = k_test_file.read(struct.unpack('>i', k_test_file.read(4))[0])
        if python_version == 3:
            objectName = objectName.decode()
        object_list.append([i, objectName, objectData])
    k_test_file.close()
    return object_list


def gen_new_name(file, objectIndex, objectName):
    return os.path.join(os.path.dirname(file),
                        objectName + str(objectIndex + 1).zfill(6),
                        os.path.basename(file).split('.')[0] + '.seed')


def gen_seed(file, data):
    if not os.path.exists(os.path.dirname(file)):
        os.makedirs(os.path.dirname(file))
    seed = open(file, 'wb')
    seed.write(data)
    seed.close()

def print_usage():
    print("usage: python transfer_ktest_to_seed.py [argument]")
    print("Remove header of ktest format file, and save the new binary file as .seed file.\n")
    print("argument:")
    print("<KtestFile>                          the path of .ktest file.")
    print("<KtestFile1> <KtestFile2> ...        the paths of .ktest files.")
    print("<KtestFolder>                        the path of folder contains .ktest file.")
    print("<KtestFolder1> <KtestFolder2> ...    the paths of folders contain .ktest file.")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print_usage()
    elif sys.argv[1] == '-h' or sys.argv[1] == 'help' or sys.argv[1] == '--help':
        print_usage()
    else:
        file_list = get_path()

        for file in file_list:
            object_list = analyse_file(file)
            for object in object_list:
                NewFileName = gen_new_name(file, object[0], object[1])
                gen_seed(NewFileName, object[2])
                print('generate %s done.' % NewFileName)