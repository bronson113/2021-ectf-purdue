# 2021 Purdue Team note:
# Bronson Yen
#
# This file removes the secret for the remove sed and update the reg_num_list file 
#

import argparse
import os
import random
def remove_secrets(scewl_id):

    # load the old list
    oldlist = open('/secrets/reg_num_list','r').read()
    oldlist = [list(map(int,i.split(','))) for i in oldlist.split('|')[1:]] 
    
    # update the list
    with open('/secrets/reg_num_list','w') as f:
        for i in oldlist: 
            if i[0]!=int(scewl_id):
                f.write('|{},{}'.format(i[0], i[1]))

    # remove the secret file for the removed sed
    os.remove('/secrets/{}.secret'.format(scewl_id))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('scewl_id', help='The SCEWL_ID of the device you want to add')
    return parser.parse_args()


def main():
    args = parse_args()
    # map of SCEWL IDs to statuses

    remove_secrets(args.scewl_id)


if __name__ == '__main__':
    main()
