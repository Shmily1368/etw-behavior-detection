#include "stdafx.h"
#include <string>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include "svm.h"
#include "svm-tool.h"
using namespace std;

#pragma warning(disable:4996)

int print_null_predict(const char *s,...) {return 0;}

static int (*info)(const char *fmt,...) = &printf;

struct svm_node *x;
int max_nr_attr = 64;

struct svm_model* pModel = nullptr;
int predict_probability=0;

static char *line = nullptr;
static int max_line_len;

void cleanup_p(FILE *test, FILE *output, const std::string &msg) {
	if (msg.size()) std::cout << msg << std::endl;
	if (line) {
		free(line);
		line = nullptr;
	}
	if (test) {
		fclose(test);
		test = nullptr;
	}
	if (output) {
		fclose(output);
		output = nullptr;
	}
}

void unload_model() {

	if (line) {
		free(line);
		line = nullptr;
	}
	if (pModel) {
		svm_free_and_destroy_model(&pModel);
		pModel = nullptr;
	}
	if (x) {
		free(x);
		x = nullptr;
	}
}

static char* readline(FILE *input)
{
	int len;

	if(fgets(line,max_line_len,input) == NULL)
		return NULL;

	while(strrchr(line,'\n') == NULL)
	{
		max_line_len *= 2;
		line = (char *) realloc(line,max_line_len);
		len = (int) strlen(line);
		if(fgets(line+len,max_line_len-len,input) == NULL)
			break;
	}
	return line;
}

// 模型加载
bool load_model(const std::string &model_file) {
	if ((pModel = svm_load_model(model_file.c_str())) == 0) {
		if (line) {
			free(line);
			line = nullptr;
		}
		return false;
	}
	else {
		x = (struct svm_node *) malloc(max_nr_attr * sizeof(struct svm_node));
		if (x == nullptr) {
			if (line) {
				free(line);
				line = nullptr;
			}
			if (pModel) {
				svm_free_and_destroy_model(&pModel);
				pModel = nullptr;
			}
			return false;
		}
	}
	return true;
}

int predict(const string& test)
{
	int svm_type = svm_get_svm_type(pModel);
	int nr_class = svm_get_nr_class(pModel);
	double *prob_estimates = NULL;

	max_line_len = 1024;
	line = (char *)malloc(max_line_len * sizeof(char));
	sprintf_s(line, max_line_len, test.c_str());

	int i = 0;
	double target_label, predict_label;
	char *idx, *val, *label, *endptr;
	int inst_max_index = -1; // strtol gives 0 if wrong format, and precomputed kernel has <index> start from 0

	label = strtok(line, " \t\n");
	if (label == NULL) { // empty line
		if (line) {
			free(line);
			line = nullptr;
		}
		exit_input_error();
		return -1;
	}

	target_label = strtod(label, &endptr);
	if (endptr == label || *endptr != '\0') {
		if (line) {
			free(line);
			line = nullptr;
		}
		exit_input_error();
		return -1;
	}

	while (1)
	{
		if (i >= max_nr_attr - 1)	// need one more for index = -1
		{
			max_nr_attr *= 2;
			x = (struct svm_node *) realloc(x, max_nr_attr * sizeof(struct svm_node));
		}

		idx = strtok(NULL, ":");
		val = strtok(NULL, " \t");

		if (val == NULL)
			break;
		errno = 0;
		x[i].index = (int)strtol(idx, &endptr, 10);
		if (endptr == idx || errno != 0 || *endptr != '\0' || x[i].index <= inst_max_index) {
			if (line) {
				free(line);
				line = nullptr;
			}
			exit_input_error();
			return -1;
		}
		else
			inst_max_index = x[i].index;

		errno = 0;
		x[i].value = strtod(val, &endptr);
		if (endptr == val || errno != 0 || (*endptr != '\0' && !isspace(*endptr))) {
			if (line) {
				free(line);
				line = nullptr;
			}
			exit_input_error();
			return -1;
		}

		++i;
	}
	x[i].index = -1;

	predict_label = svm_predict(pModel, x);
	return static_cast<int>(predict_label);
}

// unused
void predict(FILE *input, FILE *output)
{
	int correct = 0;
	int total = 0;
	double error = 0;
	double sump = 0, sumt = 0, sumpp = 0, sumtt = 0, sumpt = 0;

	int svm_type = svm_get_svm_type(pModel);
	int nr_class = svm_get_nr_class(pModel);
	double *prob_estimates = NULL;
	int j;

	if (predict_probability)
	{
		if (svm_type == NU_SVR || svm_type == EPSILON_SVR)
			info("Prob. model for test data: target value = predicted value + z,\nz: Laplace distribution e^(-|z|/sigma)/(2sigma),sigma=%g\n", svm_get_svr_probability(pModel));
		else
		{
			int *labels = (int *)malloc(nr_class * sizeof(int));
			svm_get_labels(pModel, labels);
			prob_estimates = (double *)malloc(nr_class * sizeof(double));
			fprintf(output, "labels");
			for (j = 0; j < nr_class; j++)
				fprintf(output, " %d", labels[j]);
			fprintf(output, "\n");
			free(labels);
		}
	}

	max_line_len = 1024;
	line = (char *)malloc(max_line_len * sizeof(char));
	while (readline(input) != NULL)
	{
		int i = 0;
		double target_label, predict_label;
		char *idx, *val, *label, *endptr;
		int inst_max_index = -1; // strtol gives 0 if wrong format, and precomputed kernel has <index> start from 0

		label = strtok(line, " \t\n");
		if (label == NULL) {// empty line
			exit_input_error(total + 1);
			cleanup_p(input, output, "");
			return;
		}

		target_label = strtod(label, &endptr);
		if (endptr == label || *endptr != '\0') {
			exit_input_error(total + 1);
			cleanup_p(input, output, "");
			return;
		}

		while (1)
		{
			if (i >= max_nr_attr - 1)	// need one more for index = -1
			{
				max_nr_attr *= 2;
				x = (struct svm_node *) realloc(x, max_nr_attr * sizeof(struct svm_node));
			}

			idx = strtok(NULL, ":");
			val = strtok(NULL, " \t");

			if (val == NULL)
				break;
			errno = 0;
			x[i].index = (int)strtol(idx, &endptr, 10);
			if (endptr == idx || errno != 0 || *endptr != '\0' || x[i].index <= inst_max_index) {
				exit_input_error(total + 1);
				cleanup_p(input, output, "");
				return;
			}
			else
				inst_max_index = x[i].index;

			errno = 0;
			x[i].value = strtod(val, &endptr);
			if (endptr == val || errno != 0 || (*endptr != '\0' && !isspace(*endptr))) {
				exit_input_error(total + 1);
				cleanup_p(input, output, "");
				return;
			}

			++i;
		}
		x[i].index = -1;

		if (predict_probability && (svm_type == C_SVC || svm_type == NU_SVC))
		{
			predict_label = svm_predict_probability(pModel, x, prob_estimates);
			fprintf(output, "%g", predict_label);
			for (j = 0; j < nr_class; j++)
				fprintf(output, " %g", prob_estimates[j]);
			fprintf(output, "\n");
		}
		else
		{
			predict_label = svm_predict(pModel, x);
			fprintf(output, "%.17g\n", predict_label);
		}

		if (predict_label == target_label)
			++correct;
		error += (predict_label - target_label)*(predict_label - target_label);
		sump += predict_label;
		sumt += target_label;
		sumpp += predict_label * predict_label;
		sumtt += target_label * target_label;
		sumpt += predict_label * target_label;
		++total;
	}
	if (svm_type == NU_SVR || svm_type == EPSILON_SVR)
	{
		info("Mean squared error = %g (regression)\n", error / total);
		info("Squared correlation coefficient = %g (regression)\n",
			((total*sumpt - sump * sumt)*(total*sumpt - sump * sumt)) /
			((total*sumpp - sump * sump)*(total*sumtt - sumt * sumt))
		);
	}
	else
		info("Accuracy = %g%% (%d/%d) (classification)\n",
		(double)correct / total * 100, correct, total);
	if (predict_probability)
		free(prob_estimates);
}

// old version, deprecated
int predictprevious(const char * load_model, string input)
{
	int output = -1;

	if (input == "")
	{
		fprintf(stderr, "can't open input line\n");
		return output;
	}

	if ((pModel = svm_load_model(load_model)) == 0)
	{
		fprintf(stderr, "can't open model file %s\n", load_model);
		return output;
	}

	x = (struct svm_node *) malloc(max_nr_attr*sizeof(struct svm_node));
	if (predict_probability)
	{
		if (svm_check_probability_model(pModel) == 0)
		{
			fprintf(stderr, "Model does not support probabiliy estimates\n");
			return output;
		}
	}
	else
	{
		if (svm_check_probability_model(pModel) != 0)
			info("Model supports probability estimates, but disabled in prediction.\n");
	}

	output = predict(input);
	svm_free_and_destroy_model(&pModel);
	free(x);
	return output;
}

