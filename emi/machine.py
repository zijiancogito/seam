import os
import sys
import re

def change_single_file(in_file, out_file):
    with open(in_file, 'rb') as rb:
        h_b7 = 0xb7
        h_0 = 0x0
        content =  bytearray(rb.read())
        content[18] = h_b7
        content[19] = h_0
        with open(out_file, 'wb') as wb:
            wb.write(content)

def gci(filepath):
    files = os.listdir(filepath)
    for fi in files:
        fi_d = os.path.join(filepath, fi)
        if os.path.isdir(fi_d):
            gci(fi_d)
        else:
            print(fi_d)
            print(filepath)
            d_name = os.path.dirname(fi_d)
            f_name = os.path.basename(fi_d)
            pat = r'main_o[012]-aarch64(|\-strip\-debug|\-strip\-all).o'
            if re.match(pat, f_name):
                if not os.path.exists(os.path.join(filepath,  'tmp')):
                    os.mkdir(os.path.join(filepath, 'tmp'))
                change_single_file(fi_d,
                                os.path.join(filepath, 'tmp', f_name))

if __name__ == '__main__':
    gci(sys.argv[1])
