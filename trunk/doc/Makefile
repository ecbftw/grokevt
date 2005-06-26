# $Id$

sh-var-F=$F
MAN_PAGES=1/grokevt-builddb.1 1/grokevt-parselog.1\
	 1/grokevt-ripdll.1 7/grokevt.7

build:
	mkdir -p $(BUILD_DOC)/devel
	cp *.t2t *.txt $(BUILD_DOC)
	cp devel/*.txt $(BUILD_DOC)/devel
	mkdir -p $(BUILD_DOC)/man/man1
	mkdir -p $(BUILD_DOC)/man/man7
	for F in $(foreach p,$(MAN_PAGES),man/man$(p).gz);\
		do cp $(value sh-var-F) $(BUILD_DOC)/$(value sh-var-F); done

install:
	mkdir -p $(MAN_PREFIX)/man1
	mkdir -p $(MAN_PREFIX)/man7
	cp -sf $(DOC_PREFIX)/man/man1/* $(MAN_PREFIX)/man1
	cp -sf $(DOC_PREFIX)/man/man7/* $(MAN_PREFIX)/man7


#XXX: Used during release only
$(foreach p,$(MAN_PAGES),man/man$(p)):
	txt2tags --mask-email -t man -o $@ $(notdir $@).t2t
	txt2tags --mask-email -t txt\
		-o $(basename $(notdir $@)).txt $(notdir $@).t2t

$(foreach p,$(MAN_PAGES),man/man$(p).gz): $(foreach p,$(MAN_PAGES),man/man$(p))
	gzip -c -9 $(subst .gz,,$@) > $@ && rm $(subst .gz,,$@)


release: $(foreach p,$(MAN_PAGES),man/man$(p).gz)


release-clean:
	rm -f $(foreach p,$(MAN_PAGES),man/man$(p))
	rm -f $(foreach p,$(MAN_PAGES),man/man$(p).gz)
