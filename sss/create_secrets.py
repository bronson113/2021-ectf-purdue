import argparse
import os
import random
random.seed(os.urandom(16))
def create_secrets(scewl_id):
    reg_num = random.randint(0,0xffffffff)
    print(reg_num)
    with open('/secrets/{}.secret'.format(scewl_id),'w') as f:
            f.write('''
#include "secret.h"
unsigned int get_reg_num(){
    return '''+hex(reg_num)+''';
}
''')
    with open('/secrets/reg_num_list','a') as f:
        f.write('|{},{}'.format(scewl_id, reg_num))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('scewl_id', help='The SCEWL_ID of the device you want to add')
    return parser.parse_args()


def main():
    args = parse_args()
    # map of SCEWL IDs to statuses

    create_secrets(args.scewl_id)


if __name__ == '__main__':
    main()
