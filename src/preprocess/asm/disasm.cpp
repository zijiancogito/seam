#include "disasm.h"

// compile
// g++ -std=c++17 -I ./ disasm.cpp -lgtirb -lcapstone -o disasm.o
// g++ -std=c++17 -I ./ disasm.cpp -lgtirb -lcapstone -ljsoncpp -shared -fPIC -o libdisasm.so

// TODO: add def-kill parser when disasm.

// Print Addrs in hex format
std::ostream& operator<<(std::ostream& Os, Addr A) {
  auto Flags = Os.flags();
  Os << "0x" << std::hex << std::setw(8) << std::setfill('0') << uint64_t(A);
  Os.flags(Flags);
  return Os;
}

void Disasm::register_aux_data_types() {
  using namespace gtirb::schema;
  AuxDataContainer::registerAuxDataType<FunctionEntries>();
  AuxDataContainer::registerAuxDataType<FunctionBlocks>();
}

std::string Disasm::printForTrainWithoutOperands(int line, std::map<int, std::vector<std::optional<gtirb::Addr>>> &line2ins){
  std::string asm_tmp;
  for(auto i : line2ins[line]) {
    if (this->all_insns[i]->mnemonic != "mov"){
      asm_tmp += this->all_insns[i]->mnemonic;
      asm_tmp += " ";
    }
  }
  asm_tmp += "\n";
  return asm_tmp;
}

Json::Value Disasm::printForTrainWithOperands(int line, std::map<int, std::vector<std::optional<gtirb::Addr>>> &line2ins){
  Json::Value root;
  for(auto i : line2ins[line]) {
    Json::Value insn;
    if (this->all_insns[i]->mnemonic != "mov"){
      insn["mnemonic"] = this->all_insns[i]->mnemonic;
      insn["operands"] = Json::Value(Json::arrayValue);
      for(auto j : this->all_insns[i]->operands) {
        insn["operands"].append(j);
      }
      root.append(insn);
    }
  }
  return root;
}

bool Disasm::inBlock(std::optional<gtirb::Addr> addr, block &b){
  if(addr.has_value()){
    if(b.start <= addr && addr <= b.end){
      return true;
    }
  }
  return false;
}

insn_analyzer Disasm::get_insn(std::optional<gtirb::Addr> addr){
  for(auto &f : this->bin.functions){
    for(auto &b : f.second.blocks){
      if(inBlock(addr, b.second)){
        return b.second.instructions[addr];
      }
    }
  }
  insn_analyzer empty;
  return empty;
}

int Disasm::disasm() {
  // Register the AuxData we'll want to use.
  register_aux_data_types();

  Context C;

  // Load the IR
  IR * Ir = nullptr;

  std::ifstream in(this->ir_file);
  if (auto IoE = IR::load(C, in); IoE)
    Ir = *IoE;

  if(!Ir)
    return EXIT_FAILURE;

  // Initialize capstone for decoding instructions.
  csh CsHandle;
  [[maybe_unused]] int Ret = cs_open(this->arch, this->mode, &CsHandle);
  assert(Ret == CS_ERR_OK);
  cs_option(CsHandle, CS_OPT_DETAIL, CS_OPT_ON);

  // Load function information from AuxData.
  // This information is not guaranteed to be present. For the purposes of
  // this example we assume that it exists, but real code should check for
  // nullptr in the return value of getAuxData.
  auto& FunctionEntries =
      *(Ir->modules_begin()->getAuxData<gtirb::schema::FunctionEntries>());
  auto& FunctionBlocks =
      *(Ir->modules_begin()->getAuxData<gtirb::schema::FunctionBlocks>());
  this->bin.path = this->ir_file;
  // Print function information
  std::map<boost::uuids::uuid, function> functions;
  for (auto& [Function, Entries] : FunctionEntries) {

    // Note: this prints out the function's UUID.
    // std::cout << boost::uuids::to_string(Function) << "\n";

    // Print information about entry points.
    // TODO: add symbols
    for (auto EntryUUID : Entries)
    {
      auto EntryNode = Node::getByUUID(C, EntryUUID);
      assert(EntryNode);
      auto EntryBlock = dyn_cast_or_null<CodeBlock>(EntryNode);
      assert(EntryBlock);

      // Insert the entry node into the queue.
      // std::cout << "    " << EntryBlock->getAddress() << "\n";
      this->bin.functions[boost::uuids::uuid(Function)].entry_points.push_back(EntryBlock->getAddress());
    }

    // Examine all blocks in the function.
    // std::cout << "  Blocks:\n";
    auto It = FunctionBlocks.find(Function);
    assert(It != FunctionBlocks.end());
    auto& Blocks = It->second;
    std::map<std::optional<gtirb::Addr>, block> blks;
    for (auto BlockUUID : Blocks) {
      auto BlockNode = Node::getByUUID(C, BlockUUID);
      assert(BlockNode);
      auto Block = dyn_cast_or_null<CodeBlock>(BlockNode);
      assert(Block);
      // Insert the block node into the vector.
      // std::cout << "    " << Block->getAddress() << "\n";

      // Get the instructions in the block.
      cs_insn* Insn;
      size_t count =
        cs_disasm(CsHandle, Block->rawBytes<uint8_t>(), Block->getSize(),
                  (uint64_t)Block->getAddress().value_or(Addr(0)), 0, &Insn);
      assert(count > 0);
      for (size_t I = 0; I < count; I++) {
        const auto& Inst = Insn[I];
        // auto& Detail = *Inst.detail;
        std::optional<gtirb::Addr> addr(Inst.address);
        // this->bin.functions[boost::uuids::uuid(Function)].blocks[Block->getAddress()].instructions[addr] = Insn[I];
        insn_analyzer insn;
        insn.insn = Insn[I];
        this->bin.functions[boost::uuids::uuid(Function)].blocks[Block->getAddress()].instructions[addr] = insn;
        
        if (I == 0) {
          this->bin.functions[boost::uuids::uuid(Function)].blocks[Block->getAddress()].start = addr;
        }
        if (I == count - 1) {
          this->bin.functions[boost::uuids::uuid(Function)].blocks[Block->getAddress()].end = addr;
        }
      }
    }
  }
  return EXIT_SUCCESS;
}

void Disasm::operands_pass(cs_insn &insn, std::vector<std::string> &operands) {
  switch(this->arch){
    case CS_ARCH_X86:
      this->insn_parser_x86(insn.detail->x86, operands);
      break;
    default:
      break;
  }
}

void Disasm::insn_parser_x86(cs_x86 &detail, std::vector<std::string> &operands){
  for (int i = 0; i < detail.op_count; i++)
  {
    switch(detail.operands[i].type){
      case X86_OP_REG:
        // operands.push_back(cs_reg_name(this->arch, detail.operands[i].reg));
        operands.push_back("REG");
        break;
      case X86_OP_IMM:
        operands.push_back("IMM");
        break;
      case X86_OP_MEM:
        operands.push_back("MEM");
        break;
      default:
        break;
    }
  }
}

insn_analyzer Disasm::passes(cs_insn &insn) {
  insn_analyzer ret;
  ret.mnemonic = mne_pass(insn.mnemonic);
  operands_pass(insn, ret.operands);
  return ret;
}

void Disasm::preprocess(){
  for(auto& [uuid, function] : this->bin.functions){
    for(auto& [addr, block] : function.blocks){
      for(auto& [ins_addr, instruction] : block.instructions){
        cs_insn insn = instruction.insn;
        insn_analyzer ia = passes(insn);
        ia.insn = insn;
        this->bin.functions[uuid].blocks[addr].instructions[ins_addr] = ia;
        this->all_insns[ins_addr] = &(this->bin.functions[uuid].blocks[addr].instructions[ins_addr]);
      }
    }
  }
}

//TODO: add more passes
std::string Disasm::mne_pass(char * mne) {
  std::string ret;
  ret = mne;
  return ret;
}

REG Disasm::x86_reg_parser(x86_reg reg){
  REG r;
  switch(reg){
    // General purpose registers
    // RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15
    // RAX
    case X86_REG_AH:
      r.name = "AH";
      r.type = "RAX";
      r.loc = 0x000000000000FF00;
      break;
    case X86_REG_AL:
      r.name = "AL";
      r.type = "RAX";
      r.loc = 0x00000000000000FF;
      break;
    case X86_REG_AX:
      r.name = "AX";
      r.type = "RAX";
      r.loc = 0x000000000000FFFF;
      break;
    case X86_REG_EAX:
      r.name = "EAX";
      r.type = "RAX";
      r.loc = 0x00000000FFFFFFFF;
      break;
    case X86_REG_RAX:
      r.name = "RAX";
      r.type = "RAX";
      r.loc = 0xFFFFFFFFFFFFFFFF;
      break;
    
    // RBX
    case X86_REG_BH:
      r.name = "BH";
      r.type = "RBX";
      r.loc = 0x000000000000FF00;
      break;
    case X86_REG_BL:
      r.name = "BL";
      r.type = "RBX";
      r.loc = 0x00000000000000FF;
      break;
    case X86_REG_BX:
      r.name = "RBX";
      r.loc = 0x000000000000FFFF;
      break;
    case X86_REG_EBX:
      r.name = "EBX";
      r.type = "RBX";
      r.loc = 0x00000000FFFFFFFF;
      break;
    case X86_REG_RBX:
      r.name = "RBX";
      r.type = "RBX";
      r.loc = 0xFFFFFFFFFFFFFFFF;
      break;
    // RCX
    case X86_REG_CH:
      r.name = "CH";
      r.type = "RCX";
      r.loc = 0x000000000000FF00;
      break;
    case X86_REG_CL:
      r.name = "CL";
      r.type = "RCX";
      r.loc = 0x00000000000000FF;
      break;
    case X86_REG_CX:
      r.name = "CX";
      r.type = "RCX";
      r.loc = 0x000000000000FFFF;
      break;
    case X86_REG_ECX:
      r.name = "ECX";
      r.type = "RCX";
      r.loc = 0x00000000FFFFFFFF;
      break;
    case X86_REG_RCX:
      r.name = "RCX";
      r.type = "RCX";
      r.loc = 0xFFFFFFFFFFFFFFFF;
      break;
    // RDX
    case X86_REG_DL:
      r.name = "DL";
      r.type = "RDX";
      r.loc = 0x00000000000000FF;
      break;
    case X86_REG_DH:
      r.name = "DH";
      r.type = "RDX";
      r.loc = 0x000000000000FF00;
      break;
    case X86_REG_DX:
      r.name = "DX";
      r.type = "RDX";
      r.loc = 0x000000000000FFFF;
      break;
    case X86_REG_EDX:
      r.name = "EDX";
      r.type = "RDX";
      r.loc = 0x00000000FFFFFFFF;
      break;
    case X86_REG_RDX:
      r.name = "RDX";
      r.type = "RDX";
      r.loc = 0xFFFFFFFFFFFFFFFF;
      break;
    
    // RBP
    case X86_REG_BP:
      r.name = "BP";
      r.type = "RBP";
      r.loc = 0x000000000000FFFF;
      break;
    case X86_REG_BPL:
      r.name = "BPL";
      r.type = "RBP";
      r.loc = 0x00000000000000FF;
      break;
    case X86_REG_EBP:
      r.name = "EBP";
      r.type = "RBP";
      r.loc = 0x00000000FFFFFFFF;
      break;
    case X86_REG_RBP:
      r.name = "RBP";
      r.type = "RBP";
      r.loc = 0xFFFFFFFFFFFFFFFF;
      break;
    // RSP
    case X86_REG_SP:
      r.name = "SP";
      r.type = "RSP";
      r.loc = 0x000000000000FFFF;
      break;
    case X86_REG_SPL:
      r.name = "SPL";
      r.type = "RSP";
      r.loc = 0x00000000000000FF;
      break;
    case X86_REG_ESP:
      r.name = "ESP";
      r.type = "RSP";
      r.loc = 0x00000000FFFFFFFF;
      break;
    case X86_REG_RSP:
      r.name = "RSP";
      r.type = "RSP";
      r.loc = 0xFFFFFFFFFFFFFFFF;
      break;
    // RDI
    case X86_REG_DI:
      r.name = "DI";
      r.type = "RDI";
      r.loc = 0x000000000000FFFF;
      break;
    case X86_REG_DIL:
      r.name = "DIL";
      r.type = "RDI";
      r.loc = 0x00000000000000FF;
      break;
    case X86_REG_EDI:
      r.name = "EDI";
      r.type = "RDI";
      r.loc = 0x00000000FFFFFFFF;
      break;
    case X86_REG_RDI:
      r.name = "RDI";
      r.type = "RDI";
      r.loc = 0xFFFFFFFFFFFFFFFF;
      break;
    // RSI
    case X86_REG_SI:
      r.name = "SI";
      r.type = "RSI";
      r.loc = 0x000000000000FFFF;
      break;
    case X86_REG_SIL:
      r.name = "SIL";
      r.type = "RSI";
      r.loc = 0x00000000000000FF;
      break;
    case X86_REG_ESI:
      r.name = "ESI";
      r.type = "RSI";
      r.loc = 0x00000000FFFFFFFF;
      break;
    case X86_REG_RSI:
      r.name = "RSI";
      r.type = "RSI";
      r.loc = 0xFFFFFFFFFFFFFFFF;
      break;
    // R8
    case X86_REG_R8B:
      r.name = "R8B";
      r.type = "R8";
      r.loc = 0x00000000000000FF;
      break;
    case X86_REG_R8W:
      r.name = "R8W";
      r.type = "R8";
      r.loc = 0x000000000000FFFF;
      break;
    case X86_REG_R8D:
      r.name = "R8D";
      r.type = "R8";
      r.loc = 0x00000000FFFFFFFF;
      break;
    case X86_REG_R8:
      r.name = "R8";
      r.type = "R8";
      r.loc = 0xFFFFFFFFFFFFFFFF;
      break;
    // R9
    case X86_REG_R9B:
      r.name = "R9B";
      r.type = "R9";
      r.loc = 0x00000000000000FF;
      break;
    case X86_REG_R9W:
      r.name = "R9W";
      r.type = "R9";
      r.loc = 0x000000000000FFFF;
      break;
    case X86_REG_R9D:
      r.name = "R9D";
      r.type = "R9";
      r.loc = 0x00000000FFFFFFFF;
      break;
    case X86_REG_R9:
      r.name = "R9";
      r.type = "R9";
      r.loc = 0xFFFFFFFFFFFFFFFF;
      break;
    // R10
    case X86_REG_R10B:
      r.name = "R10B";
      r.type = "R10";
      r.loc = 0x00000000000000FF;
      break;
    case X86_REG_R10W:
      r.name = "R10W";
      r.type = "R10";
      r.loc = 0x000000000000FFFF;
      break;
    case X86_REG_R10D:
      r.name = "R10D";
      r.type = "R10";
      r.loc = 0x00000000FFFFFFFF;
      break;
    case X86_REG_R10:
      r.name = "R10";
      r.type = "R10";
      r.loc = 0xFFFFFFFFFFFFFFFF;
      break;
    // R11
    case X86_REG_R11B:
      r.name = "R11B";
      r.type = "R11";
      r.loc = 0x00000000000000FF;
      break;
    case X86_REG_R11W:
      r.name = "R11W";
      r.type = "R11";
      r.loc = 0x000000000000FFFF;
      break;
    case X86_REG_R11D:
      r.name = "R11D";
      r.type = "R11";
      r.loc = 0x00000000FFFFFFFF;
      break;
    case X86_REG_R11:
      r.name = "R11";
      r.type = "R11";
      r.loc = 0xFFFFFFFFFFFFFFFF;
      break;
    // R12
    case X86_REG_R12B:
      r.name = "R12B";
      r.type = "R12";
      r.loc = 0x00000000000000FF;
      break;
    case X86_REG_R12W:
      r.name = "R12W";
      r.type = "R12";
      r.loc = 0x000000000000FFFF;
      break;
    case X86_REG_R12D:
      r.name = "R12D";
      r.type = "R12";
      r.loc = 0x00000000FFFFFFFF;
      break;
    case X86_REG_R12:
      r.name = "R12";
      r.type = "R12";
      r.loc = 0xFFFFFFFFFFFFFFFF;
      break;
    // R13
    case X86_REG_R13B:
      r.name = "R13B";
      r.type = "R13";
      r.loc = 0x00000000000000FF;
      break;
    case X86_REG_R13W:
      r.name = "R13W";
      r.type = "R13";
      r.loc = 0x000000000000FFFF;
      break;
    case X86_REG_R13D:
      r.name = "R13D";
      r.type = "R13";
      r.loc = 0x00000000FFFFFFFF;
      break;
    case X86_REG_R13:
      r.name = "R13";
      r.type = "R13";
      r.loc = 0xFFFFFFFFFFFFFFFF;
      break;
    // R14
    case X86_REG_R14B:
      r.name = "R14B";
      r.type = "R14";
      r.loc = 0x00000000000000FF;
      break;
    case X86_REG_R14W:
      r.name = "R14W";
      r.type = "R14";
      r.loc = 0x000000000000FFFF;
      break;
    case X86_REG_R14D:
      r.name = "R14D";
      r.type = "R14";
      r.loc = 0x00000000FFFFFFFF;
      break;
    case X86_REG_R14:
      r.name = "R14";
      r.type = "R14";
      r.loc = 0xFFFFFFFFFFFFFFFF;
      break;
    // R15
    case X86_REG_R15B:
      r.name = "R15B";
      r.type = "R15";
      r.loc = 0x00000000000000FF;
      break;
    case X86_REG_R15W:
      r.name = "R15W";
      r.type = "R15";
      r.loc = 0x000000000000FFFF;
      break;
    case X86_REG_R15D:
      r.name = "R15D";
      r.type = "R15";
      r.loc = 0x00000000FFFFFFFF;
      break;
    case X86_REG_R15:
      r.name = "R15";
      r.type = "R15";
      r.loc = 0xFFFFFFFFFFFFFFFF;
      break;
    // Segment registers
    case X86_REG_CS:
      r.name = "CS";
      r.type = "CS";
      r.loc = 0xFFFF;
      break;
    case X86_REG_DS:
      r.name = "DS";
      r.type = "DS";
      r.loc = 0xFFFF;
      break;
    case X86_REG_ES:
      r.name = "ES";
      r.type = "ES";
      r.loc = 0xFFFF;
      break;
    case X86_REG_FS:
      r.name = "FS";
      r.type = "FS";
      r.loc = 0xFFFF;
      break;
    case X86_REG_GS:
      r.name = "GS";
      r.type = "GS";
      r.loc = 0xFFFF;
      break;
    case X86_REG_SS:
      r.name = "SS";
      r.type = "SS";
      r.loc = 0xFFFF;
      break;
    // Control registers
    case X86_REG_EFLAGS:
      r.name = "EFLAGS";
      r.type = "RFLAGS";
      r.loc = 0x00000000FFFFFFFF;
      break;
    // RIP
    case X86_REG_IP:
      r.name = "IP";
      r.type = "RIP";
      r.loc = 0x000000000000FFFF;
      break;
    case X86_REG_EIP:
      r.name = "EIP";
      r.type = "RIP";
      r.loc = 0x00000000FFFFFFFF;
      break;
    case X86_REG_RIP:
      r.name = "RIP";
      r.type = "RIP";
      r.loc = 0xFFFFFFFFFFFFFFFF;
      break;
    case X86_REG_EIZ:
      r.name = "EIZ";
      r.type = "RIZ";
      r.loc = 0x00000000FFFFFFFF;
      break;
    case X86_REG_RIZ:
      r.name = "RIZ";
      r.type = "RIZ";
      r.loc = 0xFFFFFFFFFFFFFFFF;
      break;
    case X86_REG_FPSW:
      r.name = "FPSW";
      r.type = "FPSW";
      r.loc = 0xFFFFFFFFFFFFFFFF;
      break;
    case X86_REG_ENDING:
    case X86_REG_INVALID:
    default:
      break;
  }
  return r;
}

void Disasm::x86_mem_parser(x86_op_mem mem){
  if(mem.base != X86_REG_INVALID){
    x86_reg_parser(mem.base);
  }
  if(mem.index != X86_REG_INVALID){
    x86_reg_parser(mem.index);
  }
  if(mem.segment != X86_REG_INVALID){
    x86_reg_parser(mem.segment);
  }
}

// TODO: add df analyze for each asm code block of each line
// input: code block after passes
void Disasm::x86_df_analyze(RANGE range){
  std::map<x86_reg, cs_x86_op> reg_def;
  // extract reg map from insns
  if(range[0] != range[1]){
    for(auto &r : range){
      auto insn = this->all_insns[r];

    }
  }
}

#ifdef debug
  void Disasm::print_bin(){
    std::cout << "BIN: " << this->bin.path << "\n";
    for(auto& [uuid, function] : this->bin.functions){
      std::cout << "  FUNCTION: " << boost::uuids::to_string(uuid) << "\n";
      for(auto& [addr, block] : function.blocks){
        std::cout << "    BLOCK: " << addr << "\n";
        for(auto& [addr, instruction] : block.instructions){
          cs_insn insn = instruction.insn;
          // std::cout << "      " << addr << ": " << instruction.mnemonic << "\n";
          std::cout << "      " << addr << ": ";
          printf("%s %s 0x%x\n", insn.mnemonic, insn.op_str, insn.detail->x86.op_count);
          std::cout << "             ";
          std::cout << this->all_insns[addr]->mnemonic << " ";
          for (auto &op : block.instructions[addr].operands)
          {
            std::cout << op << " ";
          }
          // << instruction.op_str << "\n";
          std::cout << "\n";
        }
      }
    }
  }
#endif

#ifdef debug
int main(int argc, char** argv){
  Disasm D(argv[1], CS_ARCH_X86, CS_MODE_32);
  int ret = D.disasm();
  D.preprocess();
  D.print_bin();
  return ret;
}
#endif