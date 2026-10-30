import os
import re
from argparse import ArgumentParser

def filterAllfeatureByPid(strFileAllfeature,strDstPath,strDstPid,nFlterPidsDataCount):
    file_data = ""
    file_data_temp = ""
    nCount=0
    nRecord = 0
    fSum = 0
    with open(strFileAllfeature, "r", encoding="UTF-8", errors='ignore') as f:
        for line in f:
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
                if '1:' in strT and '2:' in strT:
                    for s in strT.split():
                        result.append(s.split(":")[1])
                    if nRecord>0:
                        fSum+=int(result[3])+int(result[7])
                #fSum =sum(float(n) for n in result)
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
    if nCount>nFlterPidsDataCount and fSum>10:
        with open(strDstPath,"w",encoding="UTF-8") as f:
            f.write(file_data)

def sumColumns(strFeatureFile, strOutputFile, nGroupSize):
    result = {}
    with open(strFeatureFile, 'r') as f_in, open(strOutputFile, 'w') as f_out:
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

def getPids(strFilePids):
    with open(strFilePids, 'r', encoding="UTF-8", errors='ignore') as f:
        content = f.read().strip()
        if ',' in content:
            data = content.split(',')
            if data and len(data[0])<10:
                data = [int(x) for x in data if x]
                return data

def filterByLineStart(strSrcPath,strDstPath,strLineStart):
    with open(strSrcPath, 'r') as f:
        lines = f.readlines()
    filtered_lines = [line for line in lines if line.startswith(strLineStart)]
    with open(strDstPath, 'w') as f:
        f.writelines(filtered_lines)

def SelectTop10(strInputFile, strOutputFile, nTopPercent=0.1, nTopCount=3,strSampleName='default'):
    with open(strOutputFile, 'w') as f_out:
        with open(strInputFile, 'r') as f:
            lines = f.readlines()
            sums = [(line, float(line.split()[3].split(':')[1]) + float(line.split()[7].split(':')[1])) for line in lines]
            top_percent = int(len(sums) * nTopPercent)
            if top_percent<1:
                top_percent=1
            top_lines = sorted(sums, key=lambda x: x[1], reverse=True)[:top_percent]
            if len(top_lines) > nTopCount:
                top_lines = top_lines[:nTopCount]
            for line, sum in top_lines:
                strLine='0:'
                strLine+=strSampleName
                strLine+=' '
                strLine+=line
                f_out.write(strLine)

if __name__ == '__main__':
    parser = ArgumentParser(description="Nearl") 
    parser.add_argument("--InputDir", type=str, default="Data1", help="待处理数据目录")
    parser.add_argument("--DstDir", type=str, default="Data1_Out", help="输出处理数据目录")
    parser.add_argument("--FlterPidsDataMinCount", type=str, default="10", help="过滤特征数据量小于该值的进程，通过pid区分")
    parser.add_argument("--SumColumnsMax", type=str, default="12", help="合并特征数目上限")
    args = parser.parse_args()
    print(f"Path:{args.InputDir}")
    print(f"DstPath:{args.DstDir}")
    print(f"Path:{args.FlterPidsDataMinCount}")
    print(f"DstPath:{args.SumColumnsMax}")
    strInputDir = args.InputDir
    strDstDir = args.DstDir
    if not os.path.exists(strDstDir):
        os.makedirs(strDstDir)
    nFlterPidsDataMinCount=int(args.FlterPidsDataMinCount)
    nSumColumnsMax=int(args.SumColumnsMax)
    for subdir, _, _ in os.walk(strInputDir):
        print(subdir)
        strFilePids = os.path.join(subdir, 'Pids.txt')
        strFileAllfeature = os.path.join(subdir, 'allfeature.out')
        if os.path.exists(strFilePids) and os.path.exists(strFileAllfeature):
            print(f'{strFilePids} and {strFileAllfeature} exists')
            PidList = getPids(strFilePids)
            if PidList:
                for Pid in PidList:
                    strDstPath=strDstDir+subdir[len(strInputDir):]
                    strDstPath+='_%d.txt' %Pid
                    strPid='%d' %Pid
                    filterAllfeatureByPid(strFileAllfeature,strDstPath,strPid,nFlterPidsDataMinCount)
                    if os.path.exists(strDstPath):
                        for num in range(1,nSumColumnsMax+1):
                            strSumDstPath=strDstDir
                            strSumDstPath = os.path.join(strSumDstPath, '%d' %num)
                            strSumDstAfterFilterPath=strDstDir
                            strSumDstAfterFilterPath = os.path.join(strSumDstAfterFilterPath, '%d_af' %num)
                            strTop10AfterFilterPath=strDstDir
                            strTop10AfterFilterPath = os.path.join(strTop10AfterFilterPath, '%d_10af' %num)
                            if not os.path.exists(strSumDstPath):
                                os.makedirs(strSumDstPath)
                            if not os.path.exists(strSumDstAfterFilterPath):
                                os.makedirs(strSumDstAfterFilterPath)
                            if not os.path.exists(strTop10AfterFilterPath):
                                os.makedirs(strTop10AfterFilterPath)
                            strSumDstPath+= subdir[len(strInputDir):]
                            strSumDstAfterFilterPath+= subdir[len(strInputDir):]
                            strTop10AfterFilterPath+= subdir[len(strInputDir):]
                            strSumDstPath+='_%d.txt' %Pid
                            sumColumns(strDstPath,strSumDstPath,num)
                            strSumDstAfterFilterPath+='_%d.txt' %Pid
                            filterByLineStart(strSumDstPath,strSumDstAfterFilterPath,'1')
                            strTop10AfterFilterPath+='_%d.txt' %Pid
                            strSampleName=subdir[len(strInputDir)+1:]
                            strSampleName+='_%d' %Pid
                            SelectTop10(strSumDstAfterFilterPath,strTop10AfterFilterPath,0.1,3,strSampleName)
        else:
            print(f'{strFilePids} or {strFileAllfeature} does not exist')
