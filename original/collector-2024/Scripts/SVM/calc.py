from argparse import ArgumentParser

if __name__ == '__main__':
    parser = ArgumentParser(description="Nearl") 
    parser.add_argument("--File1", type=str, default="", help="文件1")
    parser.add_argument("--File2", type=str, default="", help="文件2")
    args = parser.parse_args()
    print(f"Path:{args.File1}")
    print(f"Path:{args.File2}")
    with open(args.File1, 'r') as file1:
        with open(args.File2, 'r') as file2:
            # 初始化相同字符计数和不同字符计数
            count_1 = 0
            count_0 = 0
            count_bad_1 = 0
            count_bad_0 = 0

            # 逐行读取文件1和文件2的字符
            for line1, line2 in zip(file1, file2):
                char1 = line1[0] if line1 else ''
                char2 = line2[0] if line2 else ''
                if char1=='1':
                    count_1 += 1
                    if char1 != char2:
                        count_bad_1 += 1
                elif char1=='0':
                    count_0 += 1
                    if char1 != char2:
                        count_bad_0 += 1
            print("1：",count_bad_1, count_bad_1/count_1)
            print("0：",count_bad_0, count_bad_0/count_0)