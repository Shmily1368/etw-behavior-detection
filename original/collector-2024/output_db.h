#pragma once
#include "event_record.h"
#include "etwdata.pb.h"
#include "output.h"
#include <fstream>
#include <stdio.h>

using namespace ETWproto;
using namespace std;

#define OUTPUT_JSON_REPEAT_TIMES 10000

class OutputDb : public Output
{
public:
	OutputDb();
	~OutputDb();
	virtual bool OutputEventRecord(EventRecord* rec) override;
	virtual void DataCompress(EventRecords* rec, String* data_str) override { }	
	virtual void Clean() override {};

	BOOL OutputDb::SendRansomIpc(EventRecord* rec);
	BOOL OutputDb::SendClientProtection(EventRecord* rec);


private:
	FILE* outfile;
	String rec_json;
	unsigned int output_event_sum = 0;
	unsigned long long currentprocessevent = 0;
};

