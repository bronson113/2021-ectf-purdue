# 2021 Purdue Team note:
# Bronson Yen
#
# This file generates a random registration number for each sed that what added to the deployment
# the registration number is then stored inside the reg_num_list file for future reference
#


import argparse
import os
import random

def create_secrets(scewl_id):
    # get a random registration number
    random.seed(os.urandom(16))
    reg_num = random.randint(0,0xffffffff)
    
    # write the registration number to {scewl_id}.secret to later be copyed into each seds
    # I choose to write the secrets so that it would be compiled into the binary itself 
    # by created a secret.c file 

    with open('/secrets/{}.secret'.format(scewl_id),'w') as f:
            f.write('''
#include "secret.h"
unsigned int get_reg_num(){
    return '''+hex(reg_num)+''';
}
''')

    # Store the registration number for the sss to access and vaildate
    with open('/secrets/reg_num_list','a') as f:
        f.write('|{},{}'.format(scewl_id, reg_num))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('scewl_id', help='The SCEWL_ID of the device you want to add')
    return parser.parse_args()


def main():
    args = parse_args()
    create_secrets(args.scewl_id)


if __name__ == '__main__':
    main()
