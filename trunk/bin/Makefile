# $Id$

################################################################################

BUILD_DATABASES=$(BUILD_BIN)/build-databases
EVT_PARSER=$(BUILD_BIN)/evt-parser
RIPDLL=$(BUILD_BIN)/ripdll
FILES=$(BUILD_DATABASES) $(EVT_PARSER) $(RIPDLL)

all: $(FILES)

$(BUILD_DATABASES): build-databases
	cp build-databases $(BUILD_DATABASES)

$(EVT_PARSER): evt-parser
	cp evt-parser $(EVT_PARSER)

$(RIPDLL): ripdll
	cp ripdll $(RIPDLL)
