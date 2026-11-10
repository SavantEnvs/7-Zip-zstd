# Objects of the 7z.so build (Format7zF), compiled but not linked: the fuzz harnesses link them statically.
include makefile.gcc

.PHONY: objs
objs: $(OBJS)
