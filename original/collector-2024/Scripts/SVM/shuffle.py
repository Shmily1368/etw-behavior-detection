import random
from argparse import ArgumentParser

if __name__ == '__main__':
    parser = ArgumentParser(description="Nearl") 
    parser.add_argument("--InputFile", type=str, default="1_Feature.out", help="待处理数据")
    parser.add_argument("--ShuffleTempFile", type=str, default="1_shuffle.in", help="中间数据处理文件")
    parser.add_argument("--DstFile1", type=str, default="1_shuffle60.in", help="输出数据1")
    parser.add_argument("--DstFile2", type=str, default="1_shuffle40.in", help="输出数据2")
    parser.add_argument("--Proportion", type=str, default="0.6", help="划分比例")
    args = parser.parse_args()
    print(f"Path:{args.InputFile}")
    print(f"Path:{args.ShuffleTempFile}")
    print(f"DstPath:{args.DstFile1}")
    print(f"Path:{args.DstFile2}")
    print(f"Path:{args.Proportion}")

    out_file = open(args.ShuffleTempFile,'w',encoding='utf-8') 
    lines = []
 
    with open(args.InputFile, 'r',encoding='utf-8') as f:   
        for line in f:  
            lines.append(line)
    random.shuffle(lines)
    nums = len(lines) 
    for line in lines:
        out_file.write(line)
 
    out_file.close()

    out_file80 = open(args.DstFile1,'w',encoding='utf-8')
    out_file20 = open(args.DstFile2,'w',encoding='utf-8')

    target = nums * float(args.Proportion);
    count = 1;
    with open(args.ShuffleTempFile, 'r',encoding='utf-8') as f: 
        for line in f:
            if line[-1] != '\n':
                line += '\n'
            if(count < target):
                out_file80.write(line)
                count += 1
            else:
                out_file20.write(line)

    out_file20.close()
    out_file80.close()