#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <cassert>
#include <elf.h>
#include <map>
#include <iostream>

#include <gtirb/gtirb.hpp>
#include <regex>

#define SUCCESS 0
#define FAILURE 1

typedef std::optional<gtirb::Addr> ADDR;
typedef std ::pair<std::optional<gtirb::Addr>, std::optional<gtirb::Addr>> ADDR_RANGE;

typedef struct {
  std::string filename;
  int line;
  ADDR addr;
} debug_line;

class ReadBin
{

public:
  ReadBin(){}
  ~ReadBin(){}
};

// Parser ELF Format Files

class ReadELF: ReadBin {
public:
  std::string filename;
  std::map<std::string, Elf64_Shdr> sections;
  //TODO: add more information
  // struct DebugLine{
  //   // Elf64_Shdr header;
  //   std::map<std::optional<gtirb::Addr>, std::tuple<std::string,int>> insaddr2line;
  // };
  // std::map<std::optional<gtirb::Addr>, std::tuple<std::string,int>> insaddr2line;
  std::map<std::string, std::map<int, std::vector<ADDR_RANGE>>> line2insrange;
public:
  ReadELF(char * filename) {
    this->filename = filename;
  }
  ~ReadELF() {}

  int loadELF();
  void printAllSections();

  // run readelf to get decoded line in debug information
  // return 0 if success
  // save result to this->insaddr2line
  int getDebugLineFromReadelf();
  bool in(ADDR addr, std::vector<ADDR_RANGE> range);
  int findLine(ADDR addr);
};