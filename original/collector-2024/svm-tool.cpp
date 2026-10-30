//
// Created by fish0 on 2023/2/14.
//
#include <stdio.h>
#include <stdlib.h>
#include "svm-tool.h"


void exit_with_help(options opt)
{
	switch (opt) {
	case options::scale:
		printf(
			"Usage: svm-scale [options] data_filename\n"
			"options:\n"
			"-l lower : x scaling lower limit (default -1)\n"
			"-u upper : x scaling upper limit (default +1)\n"
			"-y y_lower y_upper : y scaling limits (default: no y scaling)\n"
			"-s save_filename : save scaling parameters to save_filename\n"
			"-r restore_filename : restore scaling parameters from restore_filename\n"
		);
		break;
	case options::train:
		printf(
			"Usage: svm-train [options] training_set_file [model_file]\n"
			"options:\n"
			"-s svm_type : set type of SVM (default 0)\n"
			"	0 -- C-SVC		(multi-class classification)\n"
			"	1 -- nu-SVC		(multi-class classification)\n"
			"	2 -- one-class SVM\n"
			"	3 -- epsilon-SVR	(regression)\n"
			"	4 -- nu-SVR		(regression)\n"
			"-t kernel_type : set type of kernel function (default 2)\n"
			"	0 -- linear: u'*v\n"
			"	1 -- polynomial: (gamma*u'*v + coef0)^degree\n"
			"	2 -- radial basis function: exp(-gamma*|u-v|^2)\n"
			"	3 -- sigmoid: tanh(gamma*u'*v + coef0)\n"
			"	4 -- precomputed kernel (kernel values in training_set_file)\n"
			"-d degree : set degree in kernel function (default 3)\n"
			"-g gamma : set gamma in kernel function (default 1/num_features)\n"
			"-r coef0 : set coef0 in kernel function (default 0)\n"
			"-c cost : set the parameter C of C-SVC, epsilon-SVR, and nu-SVR (default 1)\n"
			"-n nu : set the parameter nu of nu-SVC, one-class SVM, and nu-SVR (default 0.5)\n"
			"-p epsilon : set the epsilon in loss function of epsilon-SVR (default 0.1)\n"
			"-m cachesize : set cache memory size in MB (default 100)\n"
			"-e epsilon : set tolerance of termination criterion (default 0.001)\n"
			"-h shrinking : whether to use the shrinking heuristics, 0 or 1 (default 1)\n"
			"-b probability_estimates : whether to train a SVC or SVR pModel for probability estimates, 0 or 1 (default 0)\n"
			"-wi weight : set the parameter C of class i to weight*C, for C-SVC (default 1)\n"
			"-v n: n-fold cross validation mode\n"
			"-q : quiet mode (no outputs)\n"
		);
		break;
	case options::predict:
		printf(
			"Usage: svm-predict [options] test_file model_file output_file\n"
			"options:\n"
			"-b probability_estimates: whether to predict probability estimates, 0 or 1 (default 0); for one-class SVM only 0 is supported\n"
			"-q : quiet mode (no outputs)\n"
		);
		break;
	default:
		break;
	}

	exit(1);
}

void exit_input_error(int line_num)
{
	fprintf(stderr, "Wrong input format at line %d\n", line_num);
}

