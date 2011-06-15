# $Id$

PYTHON3_PATH:=`which python3`
PYTHON_PATH:=`which python`

# Installation prefixes.  Change to install elsewhere.
PREFIX=/usr/local
BIN_PREFIX=$(PREFIX)/bin
ETC_PREFIX=$(PREFIX)/etc/grokevt
DOC_PREFIX=$(PREFIX)/share/doc/grokevt
MAN_PREFIX=$(PREFIX)/man

################################################################################

BUILD=$(CURDIR)/build
BUILD_BIN=$(BUILD)/bin
BUILD_LIB=$(BUILD)/lib
BUILD_ETC=$(BUILD)/etc
BUILD_DOC=$(BUILD)/doc

BUILD_TREE=$(BUILD_BIN) $(BUILD_LIB) $(BUILD_ETC) $(BUILD_DOC)
SUB_DIRS=bin lib etc doc

.PHONY: $(SUB_DIRS) clean
export


all: $(BUILD_TREE) $(SUB_DIRS)

# XXX: This should be more generalized.
install: all
	mkdir -p $(BIN_PREFIX)
	mkdir -p $(ETC_PREFIX)
	mkdir -p $(DOC_PREFIX)
	cp -r $(BUILD_BIN)/* $(BIN_PREFIX)
	cp -r $(BUILD_ETC)/* $(ETC_PREFIX)
	cp -r $(BUILD_DOC)/* $(DOC_PREFIX)
	if [ "x$(PYTHON_PATH)" != "x" ]; then $(PYTHON_PATH) grokevt-distutils.py install; fi
	if [ "x$(PYTHON3_PATH)" != "x" ]; then $(PYTHON_PATH) grokevt-distutils.py install; fi
	$(MAKE) -C doc install


$(SUB_DIRS):
	$(MAKE) -C $@

$(BUILD_TREE):
	mkdir -p $@

clean:
	rm -rf $(BUILD)
