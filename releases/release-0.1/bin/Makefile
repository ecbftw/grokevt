# $Id$

################################################################################

BUILDDB=$(BUILD_BIN)/grokevt-builddb
PARSELOG=$(BUILD_BIN)/grokevt-parselog
RIPDLL=$(BUILD_BIN)/grokevt-ripdll
FILES=$(BUILDDB) $(PARSELOG) $(RIPDLL)

all: $(FILES)

$(BUILDDB): grokevt-builddb
	cp grokevt-builddb $(BUILDDB)

$(PARSELOG): grokevt-parselog
	cp grokevt-parselog $(PARSELOG)

$(RIPDLL): grokevt-ripdll
	cp grokevt-ripdll $(RIPDLL)
