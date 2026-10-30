# -*- coding: utf-8 -*-

import re
import string
import sys
import os
import json
import urllib.parse
from argparse import ArgumentParser
import csv

def update_file(strSrcPath,strDstPath):
    with open(strSrcPath, 'r') as f, open(strDstPath, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        for line in f:
            data = line.strip().split()
            row = [data[0]] + [d.split(':')[1] for d in data[1:]]
            writer.writerow(row)

if __name__ == '__main__':
    parser = ArgumentParser(description="out2csv") 
    parser.add_argument("--Path", type=str, default="out.out", help="out文件路径")
    parser.add_argument("--DstPath", type=str, default="out.csv", help="csv输出文件路径")
    args = parser.parse_args()
    print(f"Path:{args.Path}")
    print(f"DstPath:{args.DstPath}")
    if os.path.isfile(args.Path):
        update_file(args.Path,args.DstPath)
    else:
        print(f"{args.Path} is not existed")