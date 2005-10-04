# $Id$

################################################################################

SYSTEMS=$(BUILD_ETC)/systems
FILES=$(SYSTEMS)

all: $(FILES)

$(SYSTEMS):
	rm -rf $(SYSTEMS)
	cd systems && find . | grep -v '\.svn' | cpio -pmd $(SYSTEMS)
