# $Id$

################################################################################

ADDLOG=$(BUILD_BIN)/grokevt-addlog
BUILDDB=$(BUILD_BIN)/grokevt-builddb
DUMPMSGS=$(BUILD_BIN)/grokevt-dumpmsgs
FINDLOGS=$(BUILD_BIN)/grokevt-findlogs
PARSELOG=$(BUILD_BIN)/grokevt-parselog
RIPDLL=$(BUILD_BIN)/grokevt-ripdll
FILES=$(ADDLOG) $(BUILDDB) $(DUMPMSGS) $(FINDLOGS) $(PARSELOG) $(RIPDLL)

all: $(FILES)

$(ADDLOG): grokevt-addlog
	cp grokevt-addlog $(ADDLOG)

$(BUILDDB): grokevt-builddb
	cp grokevt-builddb $(BUILDDB)

$(DUMPMSGS): grokevt-dumpmsgs
	cp grokevt-dumpmsgs $(DUMPMSGS)

$(FINDLOGS): grokevt-findlogs
	cp grokevt-findlogs $(FINDLOGS)

$(PARSELOG): grokevt-parselog
	cp grokevt-parselog $(PARSELOG)

$(RIPDLL): grokevt-ripdll
	cp grokevt-ripdll $(RIPDLL)
