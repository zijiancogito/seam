ifndef VERBOSE
	QUIET:=@
endif

LLVM_CONFIG?=llvm-config-10
LLVM_CXXCONFIG = -I/usr/lib/llvm-10/include -std=c++17   -fno-exceptions -D_GNU_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS
LDFLAGS+=$(shell $(LLVM_CONFIG) --ldflags) -L/home/caoy/re_proj/seam/preprocess/lib/
LDFLAGS+=-ldl -ltinfo -lpthread -lcapstone -ldisasm -last -lgflags -ljsoncpp -lbinary-parser
COMMON_FLAGS=-Wall -Wextra
CXXFLAGS+=$(COMMON_FLAGS) $(LLVM_CXXCONFIG) -fPIC
CPPFLAGS+=$(shell $(LLVM_CONFIG) --cppflags) -I$(SRC_DIR)
INCLUDE += -I./include/

CLANGLIBS = \
	    -Wl,--start-group \
	    -lclang \
	    -lclangAST \
	    -lclangBasic \
	    -lclangFrontend \
	    -lclangLex \
	    -lclangParse \
			-lclangSema \
			-lclangSerialization \
			-lclangAnalysis \
			-lclangEdit \
			-lclangDriver \
	    -Wl,--end-group

LLVMLIBS=$(shell $(LLVM_CONFIG) --libs --system-libs)

SOURCEDIR = ./
BUILDDIR = ./

SOURCE = train

OBJECT = $(join $(addsuffix $(BUILDDIR)/, $(dir $(SOURCE))), $(notdir $(SOURCE:=.o)))

EXECUTABLE = train

all: default

default: directory $(OBJECT)
	@echo Linking Project
	$(CXX) -o $(EXECUTABLE) $(CXXFLAGS) $(OBJECT) $(CLANGLIBS)  $(LLVMLIBS) $(LDFLAGS)

directory:
	mkdir -p $(BUILDDIR)

$(BUILDDIR)/%.o : $(SOURCEDIR)/%.cpp
	@echo Compiling $*.cpp
	$(CXX) $(INCLUDE) -o $@ -c $(CPPFLAGS) $(CXXFLAGS) $<

clean:
	$(QUIET)rm -rf $(EXECUTABLE) $(BUILDDIR)