import re
from collections import defaultdict
from argparse import ArgumentParser

if __name__ == '__main__':
    parser = ArgumentParser(description="Nearl") 
    parser.add_argument("--InputFile", type=str, default="1_Feature.out", help="待处理数据")
    parser.add_argument("--InputFile1", type=str, default="1_Feature.out", help="待处理数据")
    parser.add_argument("--InputFile2", type=str, default="1_Feature.out", help="待处理数据")
    parser.add_argument("--DstFile1", type=str, default="1_shuffle60.in", help="输出数据1")
    parser.add_argument("--DstFile2", type=str, default="1_shuffle40.in", help="输出数据2")
    args = parser.parse_args()
    print(f"Path:{args.InputFile}")
    print(f"Path:{args.InputFile1}")
    print(f"Path:{args.InputFile2}")
    print(f"Path:{args.DstFile1}")
    print(f"Path:{args.DstFile2}")

    # 初始化一个字典来存储每个键的值
    data = defaultdict(list)

    # 打开并读取文件
    with open(args.InputFile, 'r') as file:
        for line in file:
            # 使用正则表达式找到所有的键值对
            pairs = re.findall(r'(\d+):(\d+\.?\d*)', line)
            # 遍历所有的键值对
            for key, value in pairs:
                # 将值添加到对应键的列表中
                data[int(key)].append(float(value))

    # 找出值始终为0的键
    zero_keys = [key for key, values in data.items() if all(value == 0.0 for value in values)]

    # 打印结果数组
    print(zero_keys)

    # 打开并读取文件
    with open(args.InputFile1, 'r') as file:
        lines = file.readlines()

    # 打开文件以写入
    with open(args.DstFile1, 'w') as file:
        for line in lines:
            # 使用正则表达式找到所有的键值对
            pairs = re.findall(r' (\d+):(\d+\.?\d*)', line)
            # 遍历所有的键值对
            for key, value in pairs:
                # 检查键是否在zero_keys中
                if int(key) in zero_keys:
                    # 如果在，删除这个键值对
                    line = line.replace(f' {key}:{value}', '')
            # 写入修改后的行到文件中
            index = line.find('2:')
            lineT = line[0]
            lineT += ' '
            lineT += line[index:]
            file.write(lineT)
            
        # 打开并读取文件
    with open(args.InputFile2, 'r') as file:
        lines = file.readlines()

    # 打开文件以写入
    with open(args.DstFile2, 'w') as file:
        for line in lines:
            # 使用正则表达式找到所有的键值对
            pairs = re.findall(r' (\d+):(\d+\.?\d*)', line)
            # 遍历所有的键值对
            for key, value in pairs:
                # 检查键是否在zero_keys中
                if int(key) in zero_keys:
                    # 如果在，删除这个键值对
                    line = line.replace(f' {key}:{value}', '')
            # 写入修改后的行到文件中
            index = line.find('2:')
            lineT = line[0]
            lineT += ' '
            lineT += line[index:]
            file.write(lineT)

