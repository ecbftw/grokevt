# $Id$

sh-var-F=$F
MAN_PAGES=1/grokevt-builddb.1 1/grokevt-parselog.1\
	 1/grokevt-ripdll.1 7/grokevt.7

install:
	mkdir -p $(BUILD_DOC)/man/man1
	mkdir -p $(BUILD_DOC)/man/man7
	for F in $(foreach p,$(MAN_PAGES),man/man$(p).gz);\
		do cp $(value sh-var-F) $(BUILD_DOC)/$(value sh-var-F); done


#XXX: Used during release only
$(foreach p,$(MAN_PAGES),man/man$(p)):
	txt2tags --mask-email -t man -o $@ $(notdir $@).txt

$(foreach p,$(MAN_PAGES),man/man$(p).gz): $(foreach p,$(MAN_PAGES),man/man$(p))
	gzip -c -9 $(subst .gz,,$@) > $@


release: $(foreach p,$(MAN_PAGES),man/man$(p).gz)


release-clean:
	rm -f $(foreach p,$(MAN_PAGES),man/man$(p))
	rm -f $(foreach p,$(MAN_PAGES),man/man$(p).gz)
