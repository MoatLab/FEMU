# /**
#  *  Copyright Notice:
#  *  Copyright 2021-2022 DMTF. All rights reserved.
#  *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
#  **/

# automatic generate .h file.
# The raw_data_key_gen.py need be used to generate raw data key after regenerating new key in sample_key.
# The generated raw data key will be consistent with the regenerating new key in sample_key.
# Run in linux: python raw_data_key_gen.py

import subprocess
import re

def extract_ec_private_key(file_path):
    output = subprocess.check_output(["openssl", "ec", "-in", file_path, "-text", "-noout"])
    output = output.decode("utf-8")

    match = re.search(r"priv:(.*?)pub:", output, re.DOTALL)
    if match:
        private_key = match.group(1).strip()
        # format 
        private_key_list = private_key.split(":")
        private_key_with_prefix = [f"0x{num}" for num in private_key_list]
        private_key_with_prefix = [num.replace('\n', '') for num in private_key_with_prefix]
        private_key_with_prefix = [num.replace('    ', '') for num in private_key_with_prefix]
        private_key_with_prefix[0] = " " + private_key_with_prefix[0]
        private_key_formatted = ", ".join(private_key_with_prefix)

        # len
        lines = [private_key_formatted[i:i+90] for i in range(0, len(private_key_formatted), 90)]
        lines = ["       " + line for line in lines]

        private_key_formatted = " \\\n".join(lines)
        return private_key_formatted
    else:
        return None

def extract_ec_public_key(file_path):
    output = subprocess.check_output(["openssl", "ec", "-in", file_path, "-text", "-noout"])
    output = output.decode("utf-8")

    match = re.search(r"pub:(.*?)ASN1 OID:", output, re.DOTALL)
    if match:
        public_key = match.group(1).strip()
        # format 
        public_key_list = public_key.split(":")
        public_key_with_prefix = [f"0x{num}" for num in public_key_list]
        public_key_with_prefix = [num.replace('\n', '') for num in public_key_with_prefix]
        public_key_with_prefix = [num.replace('    ', '') for num in public_key_with_prefix]
        public_key_with_prefix = public_key_with_prefix[1:]
        public_key_with_prefix[0] = " " + public_key_with_prefix[0]
        public_key_formatted = ", ".join(public_key_with_prefix)

        # len
        lines = [public_key_formatted[i:i+90] for i in range(0, len(public_key_formatted), 90)]
        lines = ["       " + line for line in lines]

        public_key_formatted = " \\\n".join(lines)
        return public_key_formatted
    else:
        return None

def extract_rsa_n(file_path):
    output = subprocess.check_output(["openssl", "rsa", "-in", file_path, "-text", "-noout"])
    output = output.decode("utf-8")

    match = re.search(r"modulus:(.*?)publicExponent:", output, re.DOTALL)
    if match:
        n = match.group(1).strip()
        # format 
        n_list = n.split(":")
        n_with_prefix = [f"0x{num}" for num in n_list]
        n_with_prefix = [num.replace('\n', '') for num in n_with_prefix]
        n_with_prefix = [num.replace('    ', '') for num in n_with_prefix]
        n_with_prefix[0] = " " + n_with_prefix[0]
        n_formatted = ", ".join(n_with_prefix)

        # len
        lines = [n_formatted[i:i+90] for i in range(0, len(n_formatted), 90)]
        lines = ["       " + line for line in lines]

        n_formatted = " \\\n".join(lines)
        return n_formatted
    else:
        return None

def extract_rsa_e(file_path):
    return "0x01, 0x00, 0x01"

def extract_rsa_d(file_path):
    output = subprocess.check_output(["openssl", "rsa", "-in", file_path, "-text", "-noout"])
    output = output.decode("utf-8")

    match = re.search(r"privateExponent:(.*?)prime1:", output, re.DOTALL)
    if match:
        d = match.group(1).strip()
        # format 
        d_list = d.split(":")
        d_with_prefix = [f"0x{num}" for num in d_list]
        d_with_prefix = [num.replace('\n', '') for num in d_with_prefix]
        d_with_prefix = [num.replace('    ', '') for num in d_with_prefix]
        d_with_prefix[0] = " " + d_with_prefix[0]
        d_formatted = ", ".join(d_with_prefix)

        # len
        lines = [d_formatted[i:i+90] for i in range(0, len(d_formatted), 90)]
        lines = ["       " + line for line in lines]

        d_formatted = " \\\n".join(lines)
        return d_formatted
    else:
        return None

# get ecp responder private key
m_libspdm_ec256_responder_private_key = extract_ec_private_key("./ecp256/end_responder.key")
if m_libspdm_ec256_responder_private_key:
    print("get responder ecp256 private key successfully")
else:
    print("get responder ecp256 private key failed")
m_libspdm_ec384_responder_private_key = extract_ec_private_key("./ecp384/end_responder.key")
if m_libspdm_ec384_responder_private_key:
    print("get responder ecp384 private key successfully")
else:
    print("get responder ecp384 private key failed")
m_libspdm_ec521_responder_private_key = extract_ec_private_key("./ecp521/end_responder.key")
if m_libspdm_ec521_responder_private_key:
    print("get responder ecp521 private key successfully")
else:
    print("get responder ecp521 private key failed")

# get ecp responder public key
m_libspdm_ec256_responder_public_key = extract_ec_public_key("./ecp256/end_responder.key")
if m_libspdm_ec256_responder_public_key:
    print("get responder ecp256 public key successfully")
else:
    print("get responder ecp256 public key failed")
m_libspdm_ec384_responder_public_key = extract_ec_public_key("./ecp384/end_responder.key")
if m_libspdm_ec384_responder_public_key:
    print("get responder ecp384 public key successfully")
else:
    print("get responder ecp384 public key failed")
m_libspdm_ec521_responder_public_key = extract_ec_public_key("./ecp521/end_responder.key")
if m_libspdm_ec521_responder_public_key:
    print("get responder ecp521 public key successfully")
else:
    print("get responder ecp521 public key failed")

# get ecp requester private key
m_libspdm_ec256_requester_private_key = extract_ec_private_key("./ecp256/end_requester.key")
if m_libspdm_ec256_requester_private_key:
    print("get requester ecp256 private key successfully")
else:
    print("get requester ecp256 private key failed")
m_libspdm_ec384_requester_private_key = extract_ec_private_key("./ecp384/end_requester.key")
if m_libspdm_ec384_requester_private_key:
    print("get requester ecp384 private key successfully")
else:
    print("get requester ecp384 private key failed")
m_libspdm_ec521_requester_private_key = extract_ec_private_key("./ecp521/end_requester.key")
if m_libspdm_ec521_requester_private_key:
    print("get requester ecp521 private key successfully")
else:
    print("get requester ecp521 private key failed")

# get ecp requester public key
m_libspdm_ec256_requester_public_key = extract_ec_public_key("./ecp256/end_requester.key")
if m_libspdm_ec256_requester_public_key:
    print("get requester ecp256 public key successfully")
else:
    print("get requester ecp256 public key failed")
m_libspdm_ec384_requester_public_key = extract_ec_public_key("./ecp384/end_requester.key")
if m_libspdm_ec384_requester_public_key:
    print("get requester ecp384 public key successfully")
else:
    print("get requester ecp384 public key failed")
m_libspdm_ec521_requester_public_key = extract_ec_public_key("./ecp521/end_requester.key")
if m_libspdm_ec521_requester_public_key:
    print("get requester ecp521 public key successfully")
else:
    print("get requester ecp521 public key failed")

# get rsa responder n/e/d
m_libspdm_rsa2048_res_n = extract_rsa_n("./rsa2048/end_responder.key")
if m_libspdm_rsa2048_res_n:
    print("get responder rsa2048 n successfully")
else:
    print("get responder rsa2048 n key failed")
m_libspdm_rsa2048_res_e = extract_rsa_e("./rsa2048/end_responder.key")
if m_libspdm_rsa2048_res_e:
    print("get responder rsa2048 e successfully")
else:
    print("get responder rsa2048 e key failed")
m_libspdm_rsa2048_res_d = extract_rsa_d("./rsa2048/end_responder.key")
if m_libspdm_rsa2048_res_d:
    print("get responder rsa2048 d successfully")
else:
    print("get responder rsa2048 d key failed")
m_libspdm_rsa3072_res_n = extract_rsa_n("./rsa3072/end_responder.key")
if m_libspdm_rsa3072_res_n:
    print("get responder rsa3072 n successfully")
else:
    print("get responder rsa3072 n key failed")
m_libspdm_rsa3072_res_e = extract_rsa_e("./rsa3072/end_responder.key")
if m_libspdm_rsa3072_res_e:
    print("get responder rsa3072 e successfully")
else:
    print("get responder rsa3072 e key failed")
m_libspdm_rsa3072_res_d = extract_rsa_d("./rsa3072/end_responder.key")
if m_libspdm_rsa3072_res_d:
    print("get responder rsa3072 d successfully")
else:
    print("get responder rsa3072 d key failed")
m_libspdm_rsa4096_res_n = extract_rsa_n("./rsa4096/end_responder.key")
if m_libspdm_rsa4096_res_n:
    print("get responder rsa4096 n successfully")
else:
    print("get responder rsa4096 n key failed")
m_libspdm_rsa4096_res_e = extract_rsa_e("./rsa4096/end_responder.key")
if m_libspdm_rsa4096_res_e:
    print("get responder rsa4096 e successfully")
else:
    print("get responder rsa4096 e key failed")
m_libspdm_rsa4096_res_d = extract_rsa_d("./rsa4096/end_responder.key")
if m_libspdm_rsa4096_res_d:
    print("get responder rsa4096 d successfully")
else:
    print("get responder rsa4096 d key failed")

# get rsa requester n/e/d
m_libspdm_rsa2048_req_n = extract_rsa_n("./rsa2048/end_requester.key")
if m_libspdm_rsa2048_req_n:
    print("get requester rsa2048 n successfully")
else:
    print("get requester rsa2048 n key failed")
m_libspdm_rsa2048_req_e = extract_rsa_e("./rsa2048/end_requester.key")
if m_libspdm_rsa2048_req_e:
    print("get requester rsa2048 e successfully")
else:
    print("get requester rsa2048 e key failed")
m_libspdm_rsa2048_req_d = extract_rsa_d("./rsa2048/end_requester.key")
if m_libspdm_rsa2048_req_d:
    print("get requester rsa2048 d successfully")
else:
    print("get requester rsa2048 d key failed")
m_libspdm_rsa3072_req_n = extract_rsa_n("./rsa3072/end_requester.key")
if m_libspdm_rsa3072_req_n:
    print("get requester rsa3072 n successfully")
else:
    print("get requester rsa3072 n key failed")
m_libspdm_rsa3072_req_e = extract_rsa_e("./rsa3072/end_requester.key")
if m_libspdm_rsa3072_req_e:
    print("get requester rsa3072 e successfully")
else:
    print("get requester rsa3072 e key failed")
m_libspdm_rsa3072_req_d = extract_rsa_d("./rsa3072/end_requester.key")
if m_libspdm_rsa3072_req_d:
    print("get requester rsa3072 d successfully")
else:
    print("get requester rsa3072 d key failed")
m_libspdm_rsa4096_req_n = extract_rsa_n("./rsa4096/end_requester.key")
if m_libspdm_rsa4096_req_n:
    print("get requester rsa4096 n successfully")
else:
    print("get requester rsa4096 n key failed")
m_libspdm_rsa4096_req_e = extract_rsa_e("./rsa4096/end_requester.key")
if m_libspdm_rsa4096_req_e:
    print("get requester rsa4096 e successfully")
else:
    print("get requester rsa4096 e key failed")
m_libspdm_rsa4096_req_d = extract_rsa_d("./rsa4096/end_requester.key")
if m_libspdm_rsa4096_req_d:
    print("get requester rsa4096 d successfully")
else:
    print("get requester rsa4096 d key failed")

# write key to .h
header_file = './../../os_stub/spdm_device_secret_lib_sample/raw_data_key.h'
with open(header_file, 'w') as f:

# write Copyright
    f.write('/**\n')
    f.write(' *  Copyright Notice:\n')
    f.write(' *  Copyright 2021-2022 DMTF. All rights reserved.\n')
    f.write(' *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md\n')
    f.write(' **/\n\n')

# write comment
    f.write('/*automatic generated by raw_data_key_gen.py*/\n')

# write Header Guard
    f.write('\n#ifndef RAW_DATA_KEY_H\n')
    f.write('#define RAW_DATA_KEY_H\n')

# write include .h
    f.write('\n#include "spdm_device_secret_lib_internal.h"\n')

# write ec responder key
    f.write('\n#if LIBSPDM_ECDSA_SUPPORT')
    f.write('\n#define LIBSPDM_EC256_RESPONDER_PRIVATE_KEY     { \\')
    f.write(f'\n{m_libspdm_ec256_responder_private_key},')
    f.write("}")
    f.write('\n#define LIBSPDM_EC256_RESPONDER_PUBLIC_KEY     { \\')
    f.write(f'\n{m_libspdm_ec256_responder_public_key},')
    f.write("}")
    f.write('\n\n#define LIBSPDM_EC384_RESPONDER_PRIVATE_KEY     { \\')
    f.write(f'\n{m_libspdm_ec384_responder_private_key},')
    f.write("}")
    f.write('\n#define LIBSPDM_EC384_RESPONDER_PUBLIC_KEY     { \\')
    f.write(f'\n{m_libspdm_ec384_responder_public_key},')
    f.write("}")
    f.write('\n\n#define LIBSPDM_EC521_RESPONDER_PRIVATE_KEY     { \\')
    f.write(f'\n{m_libspdm_ec521_responder_private_key},')
    f.write("}")
    f.write('\n#define LIBSPDM_EC521_RESPONDER_PUBLIC_KEY     { \\')
    f.write(f'\n{m_libspdm_ec521_responder_public_key},')
    f.write("}")

# write ec requester key
    f.write('\n\n#define LIBSPDM_EC256_REQUESTER_PRIVATE_KEY     { \\')
    f.write(f'\n{m_libspdm_ec256_requester_private_key},')
    f.write("}")
    f.write('\n#define LIBSPDM_EC256_REQUESTER_PUBLIC_KEY     { \\')
    f.write(f'\n{m_libspdm_ec256_requester_public_key},')
    f.write("}")
    f.write('\n\n#define LIBSPDM_EC384_REQUESTER_PRIVATE_KEY     { \\')
    f.write(f'\n{m_libspdm_ec384_requester_private_key},')
    f.write("}")
    f.write('\n#define LIBSPDM_EC384_REQUESTER_PUBLIC_KEY     { \\')
    f.write(f'\n{m_libspdm_ec384_requester_public_key},')
    f.write("}")
    f.write('\n\n#define LIBSPDM_EC521_REQUESTER_PRIVATE_KEY     { \\')
    f.write(f'\n{m_libspdm_ec521_requester_private_key},')
    f.write("}")
    f.write('\n#define LIBSPDM_EC521_REQUESTER_PUBLIC_KEY     { \\')
    f.write(f'\n{m_libspdm_ec521_requester_public_key},')
    f.write("}")
    f.write('\n#endif /*LIBSPDM_ECDSA_SUPPORT*/\n')

# write rsa responder n/e/d
    f.write('\n#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)')
    f.write('\n#define LIBSPDM_RSA2048_RES_N     { \\')
    f.write(f'\n{m_libspdm_rsa2048_res_n},')
    f.write("}")
    f.write('\n#define LIBSPDM_RSA2048_RES_E     {')
    f.write(f'{m_libspdm_rsa2048_res_e},')
    f.write("}")
    f.write('\n#define LIBSPDM_RSA2048_RES_D     { \\')
    f.write(f'\n{m_libspdm_rsa2048_res_d},')
    f.write("}")
    f.write('\n\n#define LIBSPDM_RSA3072_RES_N     { \\')
    f.write(f'\n{m_libspdm_rsa3072_res_n},')
    f.write("}")
    f.write('\n#define LIBSPDM_RSA3072_RES_E     {')
    f.write(f'{m_libspdm_rsa3072_res_e},')
    f.write("}")
    f.write('\n#define LIBSPDM_RSA3072_RES_D     { \\')
    f.write(f'\n{m_libspdm_rsa3072_res_d},')
    f.write("}")
    f.write('\n\n#define LIBSPDM_RSA4096_RES_N     { \\')
    f.write(f'\n{m_libspdm_rsa4096_res_n},')
    f.write("}")
    f.write('\n#define LIBSPDM_RSA4096_RES_E     {')
    f.write(f'{m_libspdm_rsa4096_res_e},')
    f.write("}")
    f.write('\n#define LIBSPDM_RSA4096_RES_D     { \\')
    f.write(f'\n{m_libspdm_rsa4096_res_d},')
    f.write("}")

# write rsa requester n/e/d
    f.write('\n\n#define LIBSPDM_RSA2048_REQ_N     { \\')
    f.write(f'\n{m_libspdm_rsa2048_req_n},')
    f.write("}")
    f.write('\n#define LIBSPDM_RSA2048_REQ_E     {')
    f.write(f'{m_libspdm_rsa2048_req_e},')
    f.write("}")
    f.write('\n#define LIBSPDM_RSA2048_REQ_D     { \\')
    f.write(f'\n{m_libspdm_rsa2048_req_d},')
    f.write("}")
    f.write('\n\n#define LIBSPDM_RSA3072_REQ_N     { \\')
    f.write(f'\n{m_libspdm_rsa3072_req_n},')
    f.write("}")
    f.write('\n#define LIBSPDM_RSA3072_REQ_E     {')
    f.write(f'{m_libspdm_rsa3072_req_e},')
    f.write("}")
    f.write('\n#define LIBSPDM_RSA3072_REQ_D     { \\')
    f.write(f'\n{m_libspdm_rsa3072_req_d},')
    f.write("}")
    f.write('\n\n#define LIBSPDM_RSA4096_REQ_N     { \\')
    f.write(f'\n{m_libspdm_rsa4096_req_n},')
    f.write("}")
    f.write('\n#define LIBSPDM_RSA4096_REQ_E     {')
    f.write(f'{m_libspdm_rsa4096_req_e},')
    f.write("}")
    f.write('\n#define LIBSPDM_RSA4096_REQ_D     { \\')
    f.write(f'\n{m_libspdm_rsa4096_req_d},')
    f.write("}")
    f.write('\n#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */\n')

# write Header Guard
    f.write('\n#endif /*RAW_DATA_KEY_H*/\n')
