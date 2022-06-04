import sys
import os


def change_single_file(in_file, out_file):
    with open(in_file, 'rb') as rb:
        h_b7 = 0xb7
        h_0 = 0x0
        content =  bytearray(rb.read())
        content[18] = h_b7
        content[19] = h_0
        with open(out_file, 'wb') as wb:
            wb.write(content)

def change_dir(in_dir, out_dir):
    for _f in os.listdir(in_dir):
        full_path = os.path.join(in_dir, _f)
        if os.path.isdir(full_path):
            print('Warning: recursive directory, skip it. ')
            continue
        out_path = os.path.join(out_dir, _f)
        print('{0} -> {1}'.format(full_path, out_path))
        change_single_file(full_path, out_path)

if __name__ == '__main__':
    parent_dir = '/home/caoy/deepdi/strip_all'
    out_parent_dir = '/home/hpw/deepdi_strip_all'
    for _d in os.listdir(parent_dir):
        full_dir = os.path.join(parent_dir, _d)
        out_full_dir = os.path.join(out_parent_dir, _d)
        if not os.path.exists(out_full_dir):
            os.system('mkdir ' + out_full_dir)
        change_dir(full_dir, out_full_dir)
