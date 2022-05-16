ifndef VERBOSE
	QUIET:=@
endif

LLVM_CONFIG?=llvm-config-10
LDFLAGS+=$(shell $(LLVM_CONFIG) --ldflags)
LDFLAGS+=-ldl -ltinfo -lpthread -ljsoncpp
COMMON_FLAGS=-Wall -Wextra -fno-rtti
CXXFLAGS+=$(COMMON_FLAGS) $(shell $(LLVM_CONFIG) --cxxflags) -fPIC
CPPFLAGS+=$(shell $(LLVM_CONFIG) --cppflags) -I$(SRC_DIR)

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
			-lclangTooling \
	    -Wl,--end-group

LLVMLIBS=$(shell $(LLVM_CONFIG) --libs --system-libs)

SOURCEDIR = ./
BUILDDIR = ./

SOURCE = ast

OBJECT = $(join $(addsuffix $(BUILDDIR)/, $(dir $(SOURCE))), $(notdir $(SOURCE:=.o)))

EXECUTABLE = libast

all: default

default: directory $(OBJECT)
	@echo Linking Project
	$(QUIET)$(CXX) -fPIC -o $(EXECUTABLE) $(CXXFLAGS) $(OBJECT) $(CLANGLIBS) $(LLVMLIBS) $(LDFLAGS)

directory:
	mkdir -p $(BUILDDIR)

$(BUILDDIR)/%.o : $(SOURCEDIR)/%.cpp
	@echo Compiling $*.cpp
	$(QUIET)$(CXX) -o $@ -c $(CPPFLAGS) $(CXXFLAGS) $<

clean:
	$(QUIET)rm -rf $(EXECUTABLE) $(BUILDDIR)