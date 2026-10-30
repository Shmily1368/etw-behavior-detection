from argparse import ArgumentParser

if __name__ == '__main__':
    parser = ArgumentParser(description="Nearl") 
    parser.add_argument("--InputFile", type=str, default="Data_total_Out\\1_af.out", help="待处理数据")
    parser.add_argument("--DstFile", type=str, default="Data_total_Out\\1_aff.out", help="输出处理数据")
    parser.add_argument("--Filter", type=str, default="50", help="过滤")
    args = parser.parse_args()
    print(f"Path:{args.InputFile}")
    print(f"DstPath:{args.DstFile}")
    print(f"DstPath:{args.Filter}")
    fFilter = float(args.Filter)
    file_data = ""
    with open(args.InputFile, "r", encoding="UTF-8", errors='ignore') as f:
        for line in f:
             fSum = 0
             result = []
             if '1:' in line and '2:' in line:
                 for s in line.split():
                    result.append(s.split(":")[1])
                 fSum+=float(result[3])+float(result[7])
             if fSum>fFilter:
                 file_data+=line
    with open(args.DstFile,"w",encoding="UTF-8") as f:
        f.write(file_data)