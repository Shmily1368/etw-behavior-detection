#pragma once
#include "IEtwEntropy.h"
#include "..\..\InterfaceCommon\MSSingleInstance.h"
#include <iostream>
#include <cmath>
#include <fstream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <sstream>
#include <xstring>
#include <unordered_map>
#include "..\..\InterfaceCommon\PykMgr.h"

const int g_num_of_files = 10;  // threshold of total number of files

class CEtwEntropy:public ICEtwEntropy
	, public CMSSingleInstance<CEtwEntropy>
{
public:
	CEtwEntropy()
	{}
	~CEtwEntropy() 
	{}

    //ansi char in
    double ICalcEntropyByFileListA(const char* szIn,const int nInSize)
    {
        std::string strIn(szIn, nInSize);
        if (strIn.empty())
            return 0;

        std::vector<std::string> vctFileList;
        std::istringstream tokenStream(strIn);
        std::string strTemp;
        while (std::getline(tokenStream, strTemp, '|')) 
        {
            if(!strTemp.empty())
                vctFileList.push_back(strTemp);
        }

        if (!vctFileList.empty())
            return entropy_as_feature(vctFileList);
        return 0;
    }

    //unicode wchar in
    double ICalcEntropyByFileListW(const wchar_t* szIn,const int nInSize)
    {
        std::wstring wcsIn(szIn, nInSize);
        std::string strIn(CPykMgrTemplate<CP_ACP>(wcsIn.c_str()));
        return ICalcEntropyByFileListA(strIn.c_str(), strIn.length());
    }

    //utf8 char in
    double ICalcEntropyByFileListUtf8(const char* szIn,const int nInSize)
    {
        std::string strIn(szIn, nInSize);
        std::wstring wcsIn(CPykMgrTemplate<CP_UTF8>(strIn.c_str()));
        std::string strInA(CPykMgrTemplate<CP_ACP>(wcsIn.c_str()));
        return ICalcEntropyByFileListA(strInA.c_str(),strInA.length());
    }

	// calculate entropy
	double calculate_entropy(const std::vector<int> counted_bytes, const std::streamsize total_length) 
	{
		double entropy = 0.;
		double temp;

		for (int i = 0; i < 256; i++) {
			temp = static_cast<double>(counted_bytes[i]) / total_length;

			if (temp > 0.)
				entropy += temp * fabs(log2(temp));
		}

		return entropy;
	}

    // provide the entropy of one file
    double entropy_of_one_file(std::string filepath)
    {
        // 16KB chunks
        std::vector<char> buff(1024 * 16, 0);
        std::streamsize total_bytes_read = 0;
        std::streamsize bytes_read = 0;

        // This vector will hold how many times every possible byte value occurs
        std::vector<int> counted_bytes(256);

        do
        {
            // Skip directories, symlinks, etc
            if (!std::filesystem::is_regular_file(filepath)) {
                //std::cerr << "\"" << filelist[i] << "\"" << " isn't a regular file, skipping." << std::endl;
                continue;
            }

            // Open the file
            std::ifstream input_file(filepath, std::ios::binary);
            if (input_file.fail()) {
                //std::cerr << "Couldn't open \"" << filelist[i] << "\" for reading." << std::endl;
                continue;
            }

            // Perform a fresh calculation
            total_bytes_read = 0;
            std::fill(counted_bytes.begin(), counted_bytes.end(), 0);

            // Read file in chunks and count the occurrences for each possible byte value (0-255)
            while (!input_file.eof()) {
                input_file.read(buff.data(), buff.size());
                bytes_read = input_file.gcount();
                total_bytes_read += bytes_read;

                for (int j = 0; j < bytes_read; j++) {
                    const unsigned char count = static_cast<unsigned char> (buff[j]);
                    counted_bytes[count]++;
                }
            }
            input_file.close();

        } while (0);

        return calculate_entropy(counted_bytes, total_bytes_read);
    }

	// provide the entropy average
	double entropy_as_feature(std::vector<std::string> filelist)
	{
		double entropy_average = 0.0;

        // entropy of different suffixes
        std::unordered_map<std::string, double> entropy_sum;
		std::unordered_map<std::string, int> entropy_count;
        // check the number of files
        if ((int)filelist.size() > g_num_of_files)
        {
            // calculate the average value of each suffix
			double entropy_now = 0.0;
            for (int i = 0; i < filelist.size(); i++)
            {
                std::string suffix_str = filelist[i].substr(filelist[i].find_last_of('.') + 1);

                entropy_now = entropy_of_one_file(filelist[i]);
				if (entropy_now < 0.01) {
					continue;
				}
				entropy_count[suffix_str]++;
				entropy_sum[suffix_str] += entropy_now;
            }

			for (const auto& t : entropy_sum) {
				auto iter = entropy_count.find(t.first);
				if (iter != entropy_count.end()) {
					double avg = t.second / static_cast<double>(iter->second);
					entropy_average = max(entropy_average, avg);
				}
			}
        }

        return std::round(entropy_average * 10000) / 10000;
	}
private:

};