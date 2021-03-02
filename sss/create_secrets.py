import argparse
import os
import random
random.seed(os.urandom(16))
def create_secrets(scewl_id):
    with open('{}.secret'.format(scewl_id),'wb') as f:
            f.write(b'''
#define REG_NUM 0xdeadbeef
''')
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
