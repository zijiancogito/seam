#include <gtirb/gtirb.hpp>
#include <capstone/capstone.h>
#include <boost/uuid/uuid_io.hpp>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <queue>
#include <vector>
#include <map>
#include <stack>
#include <jsoncpp/json/json.h>

#define debug

using namespace gtirb;

/*
  disasm result
  file: functions
    function: blocks, entry_points
      block: instructions, pre, suc (cfg)
*/

typedef std ::pair<std::optional<gtirb::Addr>, std::optional<gtirb::Addr>> RANGE;

typedef struct {
  std::string mnemonic;
  std::vector<std::string> operands;
  cs_insn insn;
  bool show;
} insn_analyzer;

typedef struct {
  // std::map<std::optional<gtirb::Addr>, cs_insn> instructions;
  std::map<std::optional<gtirb::Addr>, insn_analyzer> instructions;
  std::optional<gtirb::Addr> start;
  std::optional<gtirb::Addr> end;
  // std::vector<std::optional<gtirb::Addr>> predecessors;
  // std::vector<std::optional<gtirb::Addr>> successors;
}block;

typedef struct {
  std::map<std::optional<gtirb::Addr>, block> blocks;
  std::vector<std::optional<gtirb::Addr>> entry_points;
}function;

typedef struct {
  std::string path;
  std::map<boost::uuids::uuid, function> functions;
  // other properties
  // TODO: add more properties
}binary;

typedef struct {
  std::string type;
  std::string name;
  long int loc;
}REG;

std::ostream& operator<<(std::ostream& Os, Addr A);

class Disasm
{

public:
  std::string ir_file;
  cs_arch arch;
  cs_mode mode;

public:
  binary bin;
  std::map<std::optional<gtirb::Addr>, insn_analyzer *> all_insns;
private:
  void register_aux_data_types();

public:
  Disasm(char * ir_file, cs_arch arch, cs_mode mode) {
    this->ir_file = ir_file;
    this->arch = arch;
    this->mode = mode;
  }
  ~Disasm(){};

  // disassemble this->ir_file and save results to this->bin.
  int disasm();

  void operands_pass(cs_insn &insn, std::vector<std::string> &operands);

  void insn_parser_x86(cs_x86 &detail, std::vector<std::string> &operands);
  REG x86_reg_parser(x86_reg reg);
  void x86_mem_parser(x86_op_mem mem);

  insn_analyzer passes(cs_insn &insn);
  std::string mne_pass(char *mne);
  void preprocess();

  insn_analyzer get_insn(std::optional<gtirb::Addr> addr);

  bool inBlock(std::optional<gtirb::Addr> addr, block &b);

  std::string printForTrainWithoutOperands(int line, std::map<int, std::vector<std::optional<gtirb::Addr>>> &line2ins);
  Json::Value printForTrainWithOperands(int line, std::map<int, std::vector<std::optional<gtirb::Addr>>> &line2ins);
  void x86_df_analyze();

#ifdef debug
  void print_bin();
#endif
};