# $Id$

################################################################################

ADDLOG=$(BUILD_BIN)/grokevt-addlog
BUILDDB=$(BUILD_BIN)/grokevt-builddb
PARSELOG=$(BUILD_BIN)/grokevt-parselog
RIPDLL=$(BUILD_BIN)/grokevt-ripdll
FILES=$(BUILDDB) $(PARSELOG) $(RIPDLL) $(ADDLOG)

all: $(FILES)

$(ADDLOG): grokevt-addlog
	cp grokevt-addlog $(ADDLOG)

$(BUILDDB): grokevt-builddb
	cp grokevt-builddb $(BUILDDB)

$(PARSELOG): grokevt-parselog
	cp grokevt-parselog $(PARSELOG)

$(RIPDLL): grokevt-ripdll
	cp grokevt-ripdll $(RIPDLL)
