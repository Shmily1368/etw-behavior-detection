#include "stdafx.h"
#include <string>
#include <float.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <cmath>
using namespace std;
#pragma warning(disable:4996)


char *line = NULL;
int max_line_len = 1024;
double lower=-1.0,upper=1.0,y_lower,y_upper;
int y_scaling = 0;
double *feature_max;
double *feature_min;
double y_max = -DBL_MAX;
double y_min = DBL_MAX;
int max_index;
int min_index;
long int num_nonzeros = 0;
long int new_num_nonzeros = 0;


#define SKIP_TARGET \
    do{             \
    while(isspace(*p)) ++p;\
	while(!isspace(*p)) ++p;\
    }while(false)

#define SKIP_ELEMENT \
	do{                 \
    while(*p!=':') ++p;\
	++p;\
	while(isspace(*p)) ++p;\
	while(*p && !isspace(*p)) ++p;\
    }while(false)

//int main(int argc,char **argv)
//{
//	int i,index;
//	FILE *fp, *fp_restore = NULL;
//	char *save_filename = NULL;
//	char *restore_filename = NULL;
//
//	for(i=1;i<argc;i++)
//	{
//		if(argv[i][0] != '-') break;
//		++i;
//		switch(argv[i-1][1])
//		{
//			case 'l': lower = atof(argv[i]); break;
//			case 'u': upper = atof(argv[i]); break;
//			case 'y':
//				y_lower = atof(argv[i]);
//				++i;
//				y_upper = atof(argv[i]);
//				y_scaling = 1;
//				break;
//			case 's': save_filename = argv[i]; break;
//			case 'r': restore_filename = argv[i]; break;
//			default:
//				fprintf(stderr,"unknown option\n");
//				exit_with_help();
//		}
//	}
//
//	if(!(upper > lower) || (y_scaling && !(y_upper > y_lower)))
//	{
//		fprintf(stderr,"inconsistent lower/upper specification\n");
//		exit(1);
//	}
//
//	if(restore_filename && save_filename)
//	{
//		fprintf(stderr,"cannot use -r and -s simultaneously\n");
//		exit(1);
//	}
//
//	if(argc != i+1)
//		exit_with_help();
//
//	fp=fopen(argv[i],"r");
//
//	if(fp==NULL)
//	{
//		fprintf(stderr,"can't open file %s\n", argv[i]);
//		exit(1);
//	}
//
//	line = (char *) malloc(max_line_len*sizeof(char));
//
//#define SKIP_TARGET\
//	while(isspace(*p)) ++p;\
//	while(!isspace(*p)) ++p;
//
//#define SKIP_ELEMENT\
//	while(*p!=':') ++p;\
//	++p;\
//	while(isspace(*p)) ++p;\
//	while(*p && !isspace(*p)) ++p;
//
//	/* assumption: min index of attributes is 1 */
//	/* pass 1: find out max index of attributes */
//	max_index = 0;
//	min_index = 1;
//
//	if(restore_filename)
//	{
//		int idx, c;
//
//		fp_restore = fopen(restore_filename,"r");
//		if(fp_restore==NULL)
//		{
//			fprintf(stderr,"can't open file %s\n", restore_filename);
//			exit(1);
//		}
//
//		c = fgetc(fp_restore);
//		if(c == 'y')
//		{
//			readline(fp_restore);
//			readline(fp_restore);
//			readline(fp_restore);
//		}
//		readline(fp_restore);
//		readline(fp_restore);
//
//		while(fscanf(fp_restore,"%d %*f %*f\n",&idx) == 1)
//			max_index = max(idx,max_index);
//		rewind(fp_restore);
//	}
//
//	while(readline(fp)!=NULL)
//	{
//		char *p=line;
//
//		SKIP_TARGET
//
//		while(sscanf(p,"%d:%*f",&index)==1)
//		{
//			max_index = max(max_index, index);
//			min_index = min(min_index, index);
//			SKIP_ELEMENT
//			num_nonzeros++;
//		}
//	}
//
//	if(min_index < 1)
//		fprintf(stderr,
//			"WARNING: minimal feature index is %d, but indices should start from 1\n", min_index);
//
//	rewind(fp);
//
//	feature_max = (double *)malloc((max_index+1)* sizeof(double));
//	feature_min = (double *)malloc((max_index+1)* sizeof(double));
//
//	if(feature_max == NULL || feature_min == NULL)
//	{
//		fprintf(stderr,"can't allocate enough memory\n");
//		exit(1);
//	}
//
//	for(i=0;i<=max_index;i++)
//	{
//		feature_max[i]=-DBL_MAX;
//		feature_min[i]=DBL_MAX;
//	}
//
//	/* pass 2: find out min/max value */
//	while(readline(fp)!=NULL)
//	{
//		char *p=line;
//		int next_index=1;
//		double target;
//		double value;
//
//		if (sscanf(p,"%lf",&target) != 1)
//			return clean_up(fp_restore, fp, "ERROR: failed to read labels\n");
//		y_max = max(y_max,target);
//		y_min = min(y_min,target);
//
//		SKIP_TARGET
//
//		while(sscanf(p,"%d:%lf",&index,&value)==2)
//		{
//			for(i=next_index;i<index;i++)
//			{
//				feature_max[i]=max(feature_max[i],0);
//				feature_min[i]=min(feature_min[i],0);
//			}
//
//			feature_max[index]=max(feature_max[index],value);
//			feature_min[index]=min(feature_min[index],value);
//
//			SKIP_ELEMENT
//			next_index=index+1;
//		}
//
//		for(i=next_index;i<=max_index;i++)
//		{
//			feature_max[i]=max(feature_max[i],0);
//			feature_min[i]=min(feature_min[i],0);
//		}
//	}
//
//	rewind(fp);
//
//	/* pass 2.5: save/restore feature_min/feature_max */
//
//	if(restore_filename)
//	{
//		/* fp_restore rewinded in finding max_index */
//		int idx, c;
//		double fmin, fmax;
//		int next_index = 1;
//
//		if((c = fgetc(fp_restore)) == 'y')
//		{
//			if(fscanf(fp_restore, "%lf %lf\n", &y_lower, &y_upper) != 2 ||
//			   fscanf(fp_restore, "%lf %lf\n", &y_min, &y_max) != 2)
//				return clean_up(fp_restore, fp, "ERROR: failed to read scaling parameters\n");
//			y_scaling = 1;
//		}
//		else
//			ungetc(c, fp_restore);
//
//		if (fgetc(fp_restore) == 'x')
//		{
//			if(fscanf(fp_restore, "%lf %lf\n", &lower, &upper) != 2)
//				return clean_up(fp_restore, fp, "ERROR: failed to read scaling parameters\n");
//			while(fscanf(fp_restore,"%d %lf %lf\n",&idx,&fmin,&fmax)==3)
//			{
//				for(i = next_index;i<idx;i++)
//					if(feature_min[i] != feature_max[i])
//					{
//						fprintf(stderr,
//							"WARNING: feature index %d appeared in file %s was not seen in the scaling factor file %s. The feature is scaled to 0.\n",
//							i, argv[argc-1], restore_filename);
//						feature_min[i] = 0;
//						feature_max[i] = 0;
//					}
//
//				feature_min[idx] = fmin;
//				feature_max[idx] = fmax;
//
//				next_index = idx + 1;
//			}
//
//			for(i=next_index;i<=max_index;i++)
//				if(feature_min[i] != feature_max[i])
//				{
//					fprintf(stderr,
//						"WARNING: feature index %d appeared in file %s was not seen in the scaling factor file %s. The feature is scaled to 0.\n",
//						i, argv[argc-1], restore_filename);
//					feature_min[i] = 0;
//					feature_max[i] = 0;
//				}
//		}
//		fclose(fp_restore);
//	}
//
//	if(save_filename)
//	{
//		FILE *fp_save = fopen(save_filename,"w");
//		if(fp_save==NULL)
//		{
//			fprintf(stderr,"can't open file %s\n", save_filename);
//			exit(1);
//		}
//		if(y_scaling)
//		{
//			fprintf(fp_save, "y\n");
//			fprintf(fp_save, "%.17g %.17g\n", y_lower, y_upper);
//			fprintf(fp_save, "%.17g %.17g\n", y_min, y_max);
//		}
//		fprintf(fp_save, "x\n");
//		fprintf(fp_save, "%.17g %.17g\n", lower, upper);
//		for(i=1;i<=max_index;i++)
//		{
//			if(feature_min[i]!=feature_max[i])
//				fprintf(fp_save,"%d %.17g %.17g\n",i,feature_min[i],feature_max[i]);
//		}
//
//		if(min_index < 1)
//			fprintf(stderr,
//				"WARNING: scaling factors with indices smaller than 1 are not stored to the file %s.\n", save_filename);
//
//		fclose(fp_save);
//	}
//
//	/* pass 3: scale */
//	while(readline(fp)!=NULL)
//	{
//		char *p=line;
//		int next_index=1;
//		double target;
//		double value;
//
//		if (sscanf(p,"%lf",&target) != 1)
//			return clean_up(NULL, fp, "ERROR: failed to read labels\n");
//		output_target(target);
//
//		SKIP_TARGET
//
//		while(sscanf(p,"%d:%lf",&index,&value)==2)
//		{
//			for(i=next_index;i<index;i++)
//				output(i,0);
//
//			output(index,value);
//
//			SKIP_ELEMENT
//			next_index=index+1;
//		}
//
//		for(i=next_index;i<=max_index;i++)
//			output(i,0);
//
//		printf("\n");
//	}
//
//	if (new_num_nonzeros > num_nonzeros)
//		fprintf(stderr,
//			"WARNING: original #nonzeros %ld\n"
//			"       > new      #nonzeros %ld\n"
//			"If feature values are non-negative and sparse, use -l 0 rather than the default -l -1\n",
//			num_nonzeros, new_num_nonzeros);
//
//	free(line);
//	free(feature_max);
//	free(feature_min);
//	fclose(fp);
//	return 0;
//}

void cleanup(FILE *fp_restore, FILE *fp, const std::string& msg)
{
	if (msg.size() > 0) std::cout << msg << std::endl;
	if (line) {
		free(line);
		line = nullptr;
	}
	if (feature_max) {
		free(feature_max);
		feature_max = nullptr;
	}
	if (feature_min) {
		free(feature_min);
		feature_min = nullptr;
	}
	if (fp) {
		fclose(fp);
		fp = nullptr;
	}
	if (fp_restore) {
		fclose(fp_restore);
		fp_restore = nullptr;
	}
}

char* readline(FILE *input)
{
	int len;

	if (fgets(line, max_line_len, input) == NULL)
		return NULL;

	while (strrchr(line, '\n') == NULL)
	{
		max_line_len *= 2;
		line = (char *)realloc(line, max_line_len);
		len = (int)strlen(line);
		if (fgets(line + len, max_line_len - len, input) == NULL)
			break;
	}
	return line;
}

string output_target(double value)
{
	char x[100];
	if (y_scaling)
	{
		if (value == y_min)
			value = y_lower;
		else if (value == y_max)
			value = y_upper;
		else value = y_lower + (y_upper - y_lower) *
			(value - y_min) / (y_max - y_min);
	}
	sprintf(x, "%.17g ", value);
	return x;
}

string output(int index, double value)
{
	/* skip single-valued attribute */
	if (index == 1)
		return "";

	char x[100];
	if (feature_max[index] == feature_min[index])
		return "";

	if (value == feature_min[index])
		value = lower;
	else if (value == feature_max[index])
		value = upper;
	else
		value = lower + (upper - lower) *
		(value - feature_min[index]) /
		(feature_max[index] - feature_min[index]);

	if (value != 0)
	{
		sprintf(x, "%d:%g ", index, value);
		new_num_nonzeros++;
		return x;
	}
	return "";
}

bool load_range(const string& restore_filename)
{
	if (restore_filename.empty()) return false;

	/* assumption: min index of attributes is 1 */
	/* pass 1: find out max index of attributes */
	max_index = 0;
	min_index = 1;
	FILE *fp_restore = NULL;
	if (restore_filename.size())
	{
		int idx, c;
		fp_restore = fopen(restore_filename.c_str(), "r");
		if (fp_restore == NULL)
		{
			fprintf(stderr, "can't open file %s\n", restore_filename.c_str());
			cleanup(nullptr, nullptr, "can't open restore_filename");// add by zxw on 20191211
			return false;
		}
		line = (char*)malloc(max_line_len * sizeof(char));
		c = fgetc(fp_restore);
		if (c == 'y')
		{
			readline(fp_restore);
			readline(fp_restore);
			readline(fp_restore);
		}
		readline(fp_restore);
		readline(fp_restore);
		while (fscanf(fp_restore, "%d %*f %*f\n", &idx) == 1)
			max_index = max(idx, max_index);
		rewind(fp_restore);
	}

	feature_max = (double *)malloc((max_index + 1) * sizeof(double));
	feature_min = (double *)malloc((max_index + 1) * sizeof(double));

	if (feature_max == NULL || feature_min == NULL)
	{
		cleanup(fp_restore, nullptr, "can't allocate enough memory\n");
		return false;
	}

	for (int i = 0; i <= max_index; i++)
	{
		feature_max[i] = -DBL_MAX;
		feature_min[i] = DBL_MAX;
	}

	/* pass 2.5: save/restore feature_min/feature_max */

	if (restore_filename.size())
	{
		/* fp_restore rewinded in finding max_index */
		int idx, c;
		double fmin, fmax;
		int next_index = 1;

		if ((c = fgetc(fp_restore)) == 'y')
		{
			if (fscanf(fp_restore, "%lf %lf\n", &y_lower, &y_upper) != 2 ||
				fscanf(fp_restore, "%lf %lf\n", &y_min, &y_max) != 2) {
				cleanup(fp_restore, nullptr, "ERROR: failed to read scaling parameters\n");
				return false;
			}
			y_scaling = 1;
		}
		else
			ungetc(c, fp_restore);

		if (fgetc(fp_restore) == 'x')
		{
			if (fscanf(fp_restore, "%lf %lf\n", &lower, &upper) != 2) {
				cleanup(fp_restore, nullptr, "ERROR: failed to read scaling parameters\n");
				return false;
			}
			while (fscanf(fp_restore, "%d %lf %lf\n", &idx, &fmin, &fmax) == 3)
			{
				for (int i = next_index; i < idx; i++)
					if (feature_min[i] != feature_max[i])
					{
						//fprintf(stderr,
							//"WARNING: feature index %d appeared in line was not seen in the scaling factor file %s. The feature is scaled to 0.\n",i, restore_filename.c_str());
						feature_min[i] = 0;
						feature_max[i] = 0;
					}

				feature_min[idx] = fmin;
				feature_max[idx] = fmax;

				next_index = idx + 1;
			}

			for (int i = next_index; i <= max_index; i++)
				if (feature_min[i] != feature_max[i])
				{
					fprintf(stderr,
						"WARNING: feature index %d appeared in line was not seen in the scaling factor file %s. The feature is scaled to 0.\n",
						i, restore_filename.c_str());
					feature_min[i] = 0;
					feature_max[i] = 0;
				}
		}
		if (line) {
			free(line);
			line = nullptr;
		}
		fclose(fp_restore);
		fp_restore = nullptr;
	}

	return true;
}

void unload_range() 
{
	cleanup(nullptr, nullptr, "");
}

string scale_by_range(const string& input) 
{
	if (input[0] == '#') return "";
	int i, index;

	const char *p = input.c_str();
	SKIP_TARGET;
	while (sscanf(p, "%d:%*f", &index) == 1)
	{
		max_index = max(max_index, index);
		min_index = min(min_index, index);
		SKIP_ELEMENT;
		num_nonzeros++;
	}

	if (min_index < 1)
		fprintf(stderr,
			"WARNING: minimal feature index is %d, but indices should start from 1\n", min_index);

	if (feature_max == NULL || feature_min == NULL)
	{
		fprintf(stderr, "can't allocate enough memory\n");
		return "";
	}

	/* pass 2: find out min/max value */
	p = input.c_str();
	int next_index = 1;
	double target;
	double value;

	if (sscanf(p, "%lf", &target) != 1) {
		fprintf(stderr, "ERROR: failed to read labels\n");
		return "";
	}
	y_max = max(y_max, target);
	y_min = min(y_min, target);

	SKIP_TARGET;
	while (sscanf(p, "%d:%lf", &index, &value) == 2)
	{
		for (i = next_index; i < index; i++)
		{
			feature_max[i] = max(feature_max[i], 0);
			feature_min[i] = min(feature_min[i], 0);
		}

		feature_max[index] = max(feature_max[index], value);
		feature_min[index] = min(feature_min[index], value);

		SKIP_ELEMENT;
		next_index = index + 1;
	}
		

	for (i = next_index; i <= max_index; i++)
	{
		feature_max[i] = max(feature_max[i], 0);
		feature_min[i] = min(feature_min[i], 0);
	}

	/* pass 3: scale */
	p = input.c_str();
	next_index = 1;
	target = 0;
	value = 0;

	if (sscanf(p, "%lf", &target) != 1) {
		fprintf(stderr, "ERROR: failed to read labels\n");
		return "";
	}
	string outputs;
	outputs += output_target(target);

	SKIP_TARGET;

	while (sscanf(p, "%d:%lf", &index, &value) == 2)
	{
		for (i = next_index; i < index; i++)
			outputs += output(i, 0);

		outputs += output(index, value);

		SKIP_ELEMENT;
		next_index = index + 1;
	}

	for (i = next_index; i <= max_index; i++)
		outputs += output(i, 0);


	if (new_num_nonzeros > num_nonzeros)
		fprintf(stderr,
			"WARNING: original #nonzeros %ld\n"
			"       > new      #nonzeros %ld\n"
			"If feature values are non-negative and sparse, use -l 0 rather than the default -l -1\n",
			num_nonzeros, new_num_nonzeros);

	return outputs;
}

//unused
string scale_predict(const string& restore_filename, string input)
{
	if (restore_filename.empty()) return "";
	if (input[0] == '#') return "";
	int i, index;
	FILE *fp_restore = NULL;
	line = (char *)malloc(max_line_len*sizeof(char));



	/* assumption: min index of attributes is 1 */
	/* pass 1: find out max index of attributes */
	max_index = 0;
	min_index = 1;

	if (restore_filename.size())
	{
		int idx, c;
		fp_restore = fopen(restore_filename.c_str(), "r");
		if (fp_restore == NULL)
		{
			fprintf(stderr, "can't open file %s\n", restore_filename.c_str());
			cleanup(nullptr, nullptr, "can't open restore_filename");// add by zxw on 20191211
			return "";
		}
		c = fgetc(fp_restore);
		if (c == 'y')
		{
			readline(fp_restore);
			readline(fp_restore);
			readline(fp_restore);
		}
		readline(fp_restore);
		readline(fp_restore);
		while (fscanf(fp_restore, "%d %*f %*f\n", &idx) == 1)
			max_index = max(idx, max_index);
		rewind(fp_restore);
	}
	const char *p = input.c_str();
	SKIP_TARGET;
		while (sscanf(p, "%d:%*f", &index) == 1)
		{
			max_index = max(max_index, index);
			min_index = min(min_index, index);
			SKIP_ELEMENT;
				num_nonzeros++;
		}


	if (min_index < 1)
		fprintf(stderr,
			"WARNING: minimal feature index is %d, but indices should start from 1\n", min_index);


	feature_max = (double *)malloc((max_index + 1)* sizeof(double));
	feature_min = (double *)malloc((max_index + 1)* sizeof(double));

	if (feature_max == NULL || feature_min == NULL)
	{
		cleanup(nullptr, nullptr, "can't allocate enough memory\n");
		return "";
	}

	for (i = 0; i <= max_index; i++)
	{
		feature_max[i] = -DBL_MAX;
		feature_min[i] = DBL_MAX;
	}

	/* pass 2: find out min/max value */
	p = input.c_str();
	int next_index = 1;
	double target;
	double value;

	if (sscanf(p, "%lf", &target) != 1) {
		cleanup(fp_restore, nullptr, "ERROR: failed to read labels\n");
		return "";
	}
	y_max = max(y_max, target);
	y_min = min(y_min, target);

	SKIP_TARGET;

		while (sscanf(p, "%d:%lf", &index, &value) == 2)
		{
			for (i = next_index; i<index; i++)
			{
				feature_max[i] = max(feature_max[i], 0);
				feature_min[i] = min(feature_min[i], 0);
			}

			feature_max[index] = max(feature_max[index], value);
			feature_min[index] = min(feature_min[index], value);

			SKIP_ELEMENT;
				next_index = index + 1;
		}

	for (i = next_index; i <= max_index; i++)
	{
		feature_max[i] = max(feature_max[i], 0);
		feature_min[i] = min(feature_min[i], 0);
	}


	/* pass 2.5: save/restore feature_min/feature_max */

	if (restore_filename.size())
	{
		/* fp_restore rewinded in finding max_index */
		int idx, c;
		double fmin, fmax;
		int next_index = 1;

		if ((c = fgetc(fp_restore)) == 'y')
		{
			if (fscanf(fp_restore, "%lf %lf\n", &y_lower, &y_upper) != 2 ||
				fscanf(fp_restore, "%lf %lf\n", &y_min, &y_max) != 2) {
				cleanup(fp_restore,nullptr, "ERROR: failed to read scaling parameters\n");
				return "";
			}
			y_scaling = 1;
		}
		else
			ungetc(c, fp_restore);

		if (fgetc(fp_restore) == 'x')
		{
			if (fscanf(fp_restore, "%lf %lf\n", &lower, &upper) != 2) {
				cleanup(fp_restore, nullptr, "ERROR: failed to read scaling parameters\n");
				return "";
			}
			while (fscanf(fp_restore, "%d %lf %lf\n", &idx, &fmin, &fmax) == 3)
			{
				for (i = next_index; i<idx; i++)
					if (feature_min[i] != feature_max[i])
					{
						fprintf(stderr,
							"WARNING: feature index %d appeared in line was not seen in the scaling factor file %s. The feature is scaled to 0.\n",
							i, restore_filename.c_str());
						feature_min[i] = 0;
						feature_max[i] = 0;
					}

				feature_min[idx] = fmin;
				feature_max[idx] = fmax;

				next_index = idx + 1;
			}

			for (i = next_index; i <= max_index; i++)
				if (feature_min[i] != feature_max[i])
				{
					fprintf(stderr,
						"WARNING: feature index %d appeared in line was not seen in the scaling factor file %s. The feature is scaled to 0.\n",
						i, restore_filename.c_str());
					feature_min[i] = 0;
					feature_max[i] = 0;
				}
		}
		fclose(fp_restore);
		fp_restore = nullptr;
	}


	/* pass 3: scale */
		p = input.c_str();
		next_index = 1;
		target = 0;
		value = 0;

		if (sscanf(p, "%lf", &target) != 1) {
			cleanup(nullptr, nullptr, "ERROR: failed to read labels\n");
			return "";
		}
		string outputs;
		outputs += output_target(target);

		SKIP_TARGET;

			while (sscanf(p, "%d:%lf", &index, &value) == 2)
			{
				for (i = next_index; i<index; i++)
					outputs += output(i, 0);

				outputs += output(index, value);

				SKIP_ELEMENT;
					next_index = index + 1;
			}

		for (i = next_index; i <= max_index; i++)
			outputs += output(i, 0);


	if (new_num_nonzeros > num_nonzeros)
		fprintf(stderr,
			"WARNING: original #nonzeros %ld\n"
			"       > new      #nonzeros %ld\n"
			"If feature values are non-negative and sparse, use -l 0 rather than the default -l -1\n",
			num_nonzeros, new_num_nonzeros);
	cleanup(fp_restore, nullptr, "");

	return outputs;
}

// unused
int scale_train(const std::string& data_filename, const std::string& save_filename)
{

	//int y_scaling = 0;
	//double lower=-1.0,upper=1.0,y_lower,y_upper;

	if (data_filename.size() == 0)
	{
		std::cout << "save filename is empty\n";
		exit(1);
	}
	FILE *fp = nullptr;
	fp = fopen(data_filename.c_str(), "r");
	if (fp == nullptr)
	{
		std::cout << "can't open file " << data_filename << std::endl;
		exit(1);
	}

	line = (char *)malloc(max_line_len * sizeof(char));

	/* assumption: min index of attributes is 1 */
	/* pass 1: find out max index of attributes */
	int max_index = 0;
	int min_index = 1;
	int index = 0;
	while (readline(fp))
	{
		char *p = line;
		if (*p == '#') continue;
		SKIP_TARGET;
		while (sscanf(p, "%d:%*f", &index) == 1)
		{
			max_index = max(max_index, index);
			min_index = min(min_index, index);
			SKIP_ELEMENT;
			num_nonzeros++;
		}
	}

	if (min_index < 1)
		std::cout <<
		"WARNING: minimal feature index is" << min_index << " , but indices should start from 1\n";

	rewind(fp);

	feature_max = (double *)malloc((max_index + 1) * sizeof(double));
	feature_min = (double *)malloc((max_index + 1) * sizeof(double));

	if (feature_max == nullptr || feature_min == nullptr)
	{
		cleanup(nullptr, fp, "can't allocate enough memory");
		exit(1);
	}

	for (int i = 0; i <= max_index; i++)
	{
		feature_max[i] = -DBL_MAX;
		feature_min[i] = DBL_MAX;
	}

	/* pass 2: find out min/max value */
	while (readline(fp) != nullptr)
	{
		char *p = line;
		if (*p == '#') continue;
		int next_index = 1;
		double target;
		double value;

		if (sscanf(p, "%lf", &target) != 1)
		{
			cleanup(nullptr, fp, "ERROR: failed to read labels");
			return -1;
		}
		y_max = max(y_max, target);
		y_min = min(y_min, target);

		SKIP_TARGET;

		while (sscanf(p, "%d:%lf", &index, &value) == 2)
		{
			for (int i = next_index; i < index; i++)
			{
				feature_max[i] = max(feature_max[i], 0);
				feature_min[i] = min(feature_min[i], 0);
			}

			feature_max[index] = max(feature_max[index], value);
			feature_min[index] = min(feature_min[index], value);

			SKIP_ELEMENT;
			next_index = index + 1;
		}

		for (int i = next_index; i <= max_index; i++)
		{
			feature_max[i] = max(feature_max[i], 0);
			feature_min[i] = min(feature_min[i], 0);
		}
	}

	rewind(fp);

	/* pass 2.5: save/restore feature_min/feature_max */

	if (save_filename.size())
	{
		FILE *fp_save = fopen(save_filename.c_str(), "w");
		if (fp_save == nullptr)
		{
			cleanup(nullptr, fp, "can't open save file");
			exit(1);
		}
		fprintf(fp_save, "x\n");
		fprintf(fp_save, "%.17g %.17g\n", lower, upper);
		for (int i = 1; i <= max_index; i++)
		{
			if (feature_min[i] != feature_max[i])
				fprintf(fp_save, "%d %.17g %.17g\n", i, feature_min[i], feature_max[i]);
		}

		if (min_index < 1)
			fprintf(stderr,
				"WARNING: scaling factors with indices smaller than 1 are not stored to the file %s.\n", save_filename.c_str());
		fclose(fp_save);
		fp_save = nullptr;
	}

	/* pass 3: scale */
	while (readline(fp))
	{
		char *p = line;
		if (*p == '#') continue;
		int next_index = 1;
		double target;
		double value;

		if (sscanf(p, "%lf", &target) != 1)
		{
			cleanup(nullptr, fp, "ERROR: failed to read labels");
			return -1;
		}
			
		output_target(target);

		SKIP_TARGET;

		while (sscanf(p, "%d:%lf", &index, &value) == 2)
		{
			for (int i = next_index; i < index; i++)
				output(i, 0);

			output(index, value);

			SKIP_ELEMENT;
			next_index = index + 1;
		}

		for (int i = next_index; i <= max_index; i++)
			output(i, 0);

		printf("\n");
	}

	if (new_num_nonzeros > num_nonzeros)
		fprintf(stderr,
			"WARNING: original #nonzeros %ld\n"
			"       > new      #nonzeros %ld\n"
			"If feature values are non-negative and sparse, use -l 0 rather than the default -l -1\n",
			num_nonzeros, new_num_nonzeros);

	cleanup(nullptr, fp, "");
	return 0;
}
