import os
import re
from argparse import ArgumentParser

def filterAllfeatureByPid(strFileAllfeature,strDstPath,strDstPid,nFlterPidsDataCount):
    file_data = ""
    file_data_temp = ""
    nCount=0
    nRecord = 0
    with open(strFileAllfeature, "r", encoding="UTF-8") as f:
        for line in f:
            fSum = 0
            if "pid:" in line:
                result = re.findall(r'\d+', line)
                if strDstPid == result[0]:
                #if strDstPid in result:
                    #print(f"{strDstPid} is Founded")
                    nRecord += 2
                    nCount += 1
            elif "=====" in line:
                nRecord += 1
            else:
                result = []
                strT = line[2:]
                for s in strT.split():
                    result.append(s.split(":")[1])
                fSum =sum(float(n) for n in result)
            if nRecord>0:
                if "pid:" in line:
                    file_data_temp += line
                elif "=====" in line:
                    file_data_temp += line
                else:
                    file_data_temp += "1 "
                    file_data_temp += line[2:]
                nRecord -=1
            file_data+=file_data_temp
            file_data_temp=""            
    if nCount>nFlterPidsDataCount:
        with open(strDstPath,"w",encoding="UTF-8") as f:
            f.write(file_data)

def sumColumns(strFeatureFile, strOutputFile, nGroupSize):
    result = {}
    with open(strFeatureFile, 'r', errors='ignore') as f_in, open(strOutputFile, 'w') as f_out:
        nTimeStampCount = 0
        nPid=0
        for line in f_in:
            line = line.strip()
            if not line:
                continue
            elif "=====" in line:
                nTimeStampCount+=1
                if (nTimeStampCount-1) % nGroupSize == 0:
                    f_out.write(line)
                    f_out.write('\n')
                    for strPid in result:
                        f_out.write('PID:')
                        f_out.write(strPid)
                        f_out.write('\n')
                        for key in sorted(result[strPid].keys()):
                            f_out.write(f'{key}:{result[strPid][key]} ')
                        f_out.write('\n')
                    result.clear()
            elif "pid:" in line:
                nPid = re.findall(r'\d+', line)[0]
                if not result.get(nPid):
                    result[nPid] = {}
            else:
                parts = line.split()
                for part in parts[1:]:
                    key, value = part.split(':')
                    key = int(key)
                    value = float(value)
                    result[nPid][key] = result[nPid].get(key, 0) + value

        if result:
            for strPid in result:
                f_out.write('PID:')
                f_out.write(strPid)
                f_out.write('\n')
                for key in sorted(result[strPid].keys()):
                    f_out.write(f'{key}:{result[strPid][key]} ')
                f_out.write('\n')
            result.clear()

def filterByLineStart(strSrcPath,strDstPath,strLineStart):
    with open(strSrcPath, 'r') as f:
        lines = f.readlines()
    filtered_lines = [line for line in lines if line.startswith(strLineStart)]
    with open(strDstPath, 'w') as f:
        f.writelines(filtered_lines)

def ExtractPids(input_file,min_count=5):
    pids = {}
    with open(input_file, 'r', errors='ignore') as f_in:
        for line in f_in:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            for i, part in enumerate(parts):
                if part == 'pid:':
                    pid = int(parts[i+1])
                    pids[pid] = pids.get(pid, 0) + 1
    return pids

if __name__ == '__main__':
    parser = ArgumentParser(description="Nearl") 
    parser.add_argument("--InputFile", type=str, default="allfeature_setup.out", help="待处理良性进程数据")
    parser.add_argument("--DstDir", type=str, default="allfeature_setup", help="输出处理数据目录")
    parser.add_argument("--SumColumnsMax", type=str, default="12", help="合并特征数目上限")
    args = parser.parse_args()
    print(f"Path:{args.InputFile}")
    print(f"DstPath:{args.DstDir}")
    print(f"DstPath:{args.SumColumnsMax}")

    strInputFile = args.InputFile
    strOutputDir = args.DstDir
    if not os.path.exists(strOutputDir):
        os.makedirs(strOutputDir)
    nSumColumnsMax=int(args.SumColumnsMax)

    listPids=ExtractPids(strInputFile,0)
    if listPids:
        for Pid in listPids:
            strDstPath=strOutputDir
            strDstPath+='\\_%d.txt' %Pid
            strPid='%d' %Pid
            filterAllfeatureByPid(strInputFile,strDstPath,strPid,-1)
            if os.path.exists(strDstPath):
                for num in range(1,nSumColumnsMax+1):
                    strSumDstPath=strOutputDir
                    strSumDstPath = os.path.join(strSumDstPath, '%d' %num)
                    strSumDstAfterFilterPath=strOutputDir
                    strSumDstAfterFilterPath = os.path.join(strSumDstAfterFilterPath, '%d_af' %num)
                    if not os.path.exists(strSumDstPath):
                        os.makedirs(strSumDstPath)
                    if not os.path.exists(strSumDstAfterFilterPath):
                        os.makedirs(strSumDstAfterFilterPath)
                    strSumDstPath+='\\_%d.txt' %Pid
                    sumColumns(strDstPath,strSumDstPath,num)
                    strSumDstAfterFilterPath+='\\_%d.txt' %Pid
                    filterByLineStart(strSumDstPath,strSumDstAfterFilterPath,'1')