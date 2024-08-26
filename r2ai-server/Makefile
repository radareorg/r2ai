PWD=$(shell pwd)
R2PM_BINDIR=$(shell r2pm -H R2PM_BINDIR)
R2_BINDIR=$(shell r2 -H R2_BINDIR)

install:
	cp -f r2ai-server $(R2_BINDIR)/r2ai-server || echo Maybe use user-install instead?

uninstall:
	rm -f $(R2_BINDIR)/r2ai-server

user-install:
	ln -fs $(PWD)/r2ai-server $(R2PM_BINDIR)/r2ai-server

user-uninstall:
	rm -f $(R2PM_BINDIR)/r2ai-server

