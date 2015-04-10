#ifndef _TEST_H_
#define _TEST_H_

struct np_test_capab {
	char* capab;
	char** attributes;
	char** values;
	unsigned int attr_count;

	char* not_older_revision;
	char* exact_revision;
	char** features;
	unsigned int feature_count;
	char** not_features;
	unsigned int not_feature_count;
	struct np_test_capab* next;
};

struct np_test_var {
	char* name;
	unsigned int value_range_start;
	unsigned int value_range_step;
	enum np_test_var_range_op {
		ADD,
		SUB,
		MUL,
		DIV
	} value_range_op;
	char** value_list;
	unsigned int value_list_count;
	struct np_test_var* next;
};

struct np_test_cmd {
	unsigned int id;
	char* cmd;
	char* file;
	char* result_err_tag;
	char* result_err_msg;
	char* result_file;
	struct np_test_cmd* next;
};

struct np_test {
	char* name;
	unsigned int count;
	struct np_test_capab* required_capabs;
	struct np_test_var* vars;
	struct np_test_cmd* cmds;
	struct np_test* next;
};

void np_test_capab_free(struct np_test_capab* capab);

void np_test_var_free(struct np_test_var* var);

void np_test_cmd_free(struct np_test_cmd* cmd);

void np_test_free(struct np_test* test);

int perform_test(struct np_test* tests, struct np_test_capab* global_capabs, struct np_test_var* global_vars, const struct nc_cpblts* capabs, FILE* output);

#endif /* _TEST_H_ */