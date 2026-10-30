#pragma once
enum class options {
	scale = 0,
	train = 1,
	predict = 2
};


void exit_with_help(options opt);

void exit_input_error(int line_num = 0);