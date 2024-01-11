# radare2

## Configuration

These eval vars can be changed with the `-e` command and commandline flag:

* anal.a2f: use the new WIP analysis algorithm (core/p/a2f), anal.depth ignored atm
* anal.arch: select the architecture to use
* anal.armthumb: aae computes arm/thumb changes (lot of false positives ahead)
* anal.autoname: speculatively set a name for the functions, may result in some false positives
* anal.bb.maxsize: maximum basic block size
* anal.brokenrefs: follow function references as well if function analysis was failed
* anal.calls: make basic af analysis walk into calls
* anal.cc: specify default calling convention
