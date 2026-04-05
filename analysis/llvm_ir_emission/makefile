CURDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
WORKBENCH := $(CURDIR)
DECOMPILED := $(wildcard decompiled/*.c)
DECOMPILED_BC := $(patsubst %.c, %.bc, $(DECOMPILED))

# Changed -O1 to -O0 to ensure bitcode is generated without optimizations
CLANG_FLAGS := -c -emit-llvm -O0 -xc++ -std=c++17 \
	-Wno-c++11-narrowing \
	-g \
	-gcolumn-info \
	-fdebug-info-for-profiling \
	-fno-discard-value-names \
	-fno-inline-functions \
	-I$(WORKBENCH) \
	-I$(WORKBENCH)/decompiled

# Note: lld-link usually produces an .exe or .dll. 
# so thats why i use llvm-link for .bc
recompiled_llvm: $(DECOMPILED_BC)
	@where llvm-link
	llvm-link $(DECOMPILED_BC) -o recompiled.bc
	llvm-dis recompiled.bc -o recompiled.ll
	@echo "FINISHED LINKING RECOMPILED BITCODE"

%.bc: %.c
	clang $(CLANG_FLAGS) -o $@ $<

clean:
	rm -f $(DECOMPILED_BC) recompiled.bc recompiled.ll

.PHONY: clean