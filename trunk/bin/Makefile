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
	install -m 0755 grokevt-addlog $(ADDLOG)

$(BUILDDB): grokevt-builddb
	install -m 0755 grokevt-builddb $(BUILDDB)

$(DUMPMSGS): grokevt-dumpmsgs
	install -m 0755 grokevt-dumpmsgs $(DUMPMSGS)

$(FINDLOGS): grokevt-findlogs
	install -m 0755 grokevt-findlogs $(FINDLOGS)

$(PARSELOG): grokevt-parselog
	install -m 0755 grokevt-parselog $(PARSELOG)

$(RIPDLL): grokevt-ripdll
	install -m 0755 grokevt-ripdll $(RIPDLL)
