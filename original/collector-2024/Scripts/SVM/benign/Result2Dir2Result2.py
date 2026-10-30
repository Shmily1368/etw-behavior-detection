import os
from argparse import ArgumentParser

def extract_lines(input_folder, output_file, line_start):
    with open(output_file, 'w') as f_out:
        for root, dirs, files in os.walk(input_folder):
            for file in files:
                with open(os.path.join(root, file), 'r') as f_in:
                    for line in f_in:
                        if line.startswith(line_start):
                            f_out.write(line)
                            
if __name__ == '__main__':
    parser = ArgumentParser(description="筛选out文件信息") 
    parser.add_argument("--Dir", type=str, default="test", help="文件夹路径")
    parser.add_argument("--DstPath", type=str, default="output.result2", help="输出文件路径")
    parser.add_argument("--LineStart", type=str, default="1", help="行开头筛选")
    args = parser.parse_args()
    print(f"Dir:{args.Dir}")
    print(f"DstPath:{args.DstPath}")
    print(f"DstPath:{args.LineStart}")
    extract_lines(args.Dir, args.DstPath,args.LineStart)