DECAI_CORE_WD=$(LIBR)/xps/p/decai
DECAI_CORE_OBJ= \
	$(DECAI_CORE_WD)/r2plugin/core/plugin.o \
	$(DECAI_CORE_WD)/r2plugin/core/decai.r2.js.o
EXTERNAL_STATIC_OBJS+=$(DECAI_CORE_OBJ)

# decai.r2.js can be rebuilt from typescript with r2frida-compile (make -C src)
$(DECAI_CORE_WD)/r2plugin/core/decai.r2.js.c: $(DECAI_CORE_WD)/decai.r2.js
	rax2 -C < $(DECAI_CORE_WD)/decai.r2.js | \
		sed -e 's,^unsigned,const unsigned,' -e 's,buf,decai_qjs,g' > $@
