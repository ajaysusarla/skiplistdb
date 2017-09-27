# Tests
-include ../config.mk

TEST_RESULTS_DIR = results

all: test

test: clean prep

prep:
	$(SDB_MKDIR) -p $(TEST_RESULTS_DIR)

clean:
	$(SDB_RM) $(TEST_RESULTS_DIR)

