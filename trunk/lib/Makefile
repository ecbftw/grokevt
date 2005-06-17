# $Id$

################################################################################

GROKEVT=$(BUILD_LIB)/grokevt.py
FILES=$(GROKEVT)

all: $(FILES)

$(GROKEVT): grokevt.py
	cp grokevt.py $(GROKEVT)
	echo 'PATH_CONFIG="$(ETC_PREFIX)"' >> $(GROKEVT)
