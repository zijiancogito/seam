#include <capstone/capstone.h>
#include <libgen.h>
#include <clang/AST/Stmt.h>
#include <gtirb/gtirb.hpp>
#include <dirent.h>
#include <gflags/gflags.h>
#include <jsoncpp/json/json.h>
#include "disasm.h"
#include "ast.h"
#include "binary-parser.h"


// ./train -batch=1 -ir ../test/example/case1/case1-x64.ir -bin ../test/example/case1/case1-x64.o -src ../test/example/case1/case1.c -out ./

void printAsm(){

}

void pair(char* ir_file, char* bin_file, char* src_file, cs_mode mode, cs_arch arch, std::vector<std::string>& asm_str, std::vector<std::string>& ast_str, bool withOperands=true) {
  // disassemble
  std::cout << "Disassembling..." << std::endl;
  Disasm S(ir_file, arch, mode);
  int ret = S.disasm();
  S.preprocess();
  
  // ast
  std::cout << "Parsing AST..." << std::endl;
  ASTManager ast;
  // "anything", "source file", "--filter=funcname"
  const char * params[1];
  char * p0 = "anything";
  params[0] = p0;
  // std::cout << src_file << std::endl;
  ast.load(1, params, src_file, "func_1");
  ast.TraverseAllFunctions();

  // map
  std::cout << "GetDebug..." << std::endl;
  ReadELF debuginf(bin_file);
  int ret2 = debuginf.getDebugLineFromReadelf();
  if (ret2 != 0) {
    std::cerr << "Error: cannot get debug line from readelf" << std::endl;
    exit(0);
  }

  // for(auto &it : debuginf.line2insrange) {
  //   std::cout << it.first << std::endl;
  //   for(auto &it2 : it.second) {
  //     std::cout << it2.first << " ";
  //     for(auto &it3 : it2.second) {
  //       std::cout << "(" << it3.first << " " << it3.second << ") ";
  //     }
  //     std::cout << std::endl;
  //   }
  // }

  if(debuginf.line2insrange.find(basename(src_file)) == debuginf.line2insrange.end()) {
    std::cerr << "Error: cannot find debug line in debuginf" << std::endl;
    exit(0);
  }

  //line2ins
  std::cout << "Get line2ins..." << std::endl;
  std::map<int, std::vector<ADDR>> line2ins;
  for(auto &f : S.bin.functions){
    for(auto &b : f.second.blocks) {
      for(auto &i : b.second.instructions) {
        line2ins[debuginf.findLine(i.first)].push_back(i.first);
      }
    }
  }

  // TODO:
  // for (auto &[l, ranges] : debuginf.line2insrange[basename(src_file)]) {
    
  // }
  // S.df_analyze();
  // ast.df_analyze();

  // pair
  // std::vector<std::string> asm_str, ast_str;
  std::cout << "Pairing..." << std::endl;
  for(auto &[l, ranges] : debuginf.line2insrange[basename(src_file)]) {
    // get asm
    if(withOperands) {
      Json::Value asm_json = S.printForTrainWithOperands(l, line2ins);
      Json::FastWriter fastWriter;
      std::string tmp = fastWriter.write(asm_json);
      asm_str.push_back(tmp);
    }
    else {
      asm_str.push_back(S.printForTrainWithoutOperands(l, line2ins));
    }
    // get ast
    if(withOperands) {
      Json::Value ast_json = ast.printForTrainWithOperands(basename(src_file), l);
      Json::FastWriter fastWriter;
      std::string tmp = fastWriter.write(ast_json);
      ast_str.push_back(tmp);
    }
    else {
      ast_str.push_back(ast.printForTrainWithoutOperands(basename(src_file), l));
    }
  }
}


void writeData(std::vector<std::string>& asm_str, std::vector<std::string>& ast_str, const char* out_asm_file, const char* out_ast_file){
  std::ofstream osfs(out_asm_file);
  std::ofstream oafs(out_ast_file);
  for (int i = 0; i < asm_str.size(); i++)
  {
    osfs << asm_str[i] << "\n";
    oafs << ast_str[i] << "\n";
  }
  osfs.close();
  oafs.close();
}

//char* ir_file, char* bin_file, char* src_file, cs_mode mode, cs_arch arch, std::vector<std::string>& asm_str, std::vector<std::string>& ast_str
int batch_preprocess(char* bin_dir, char* ir_dir, char* src_dir, char* out_dir, cs_mode mode=CS_MODE_64, cs_arch arch=CS_ARCH_X86, bool withOperands=true){
  DIR *dir;
  struct dirent *ent;
  if ((dir = opendir (bin_dir)) != NULL) {
    while ((ent = readdir (dir)) != NULL) {
      if(ent->d_name[0] == '.') continue;
      // std::cout << ent->d_name << std::endl;
      std::string tmp = ent->d_name;
      std::string bname = tmp.substr(0, tmp.rfind('.'));
      std::string bin_file = std::string(bin_dir) + "/" + ent->d_name;
      std::string ir_file = std::string(ir_dir) + "/" + ent->d_name + ".ir";
      std::string src_file = std::string(src_dir) + "/" + bname + ".c";
      std::string out_asm_file = std::string(out_dir) + "/" + bname + ".asm.txt";
      std::string out_ast_file = std::string(out_dir) + "/" + bname + ".ast.txt";
      std::vector<std::string> asm_str, ast_str;
      pair((char*)(ir_file.c_str()), (char*)(bin_file.c_str()), (char*)(src_file.c_str()), mode, arch, asm_str, ast_str, withOperands);
      writeData(asm_str, ast_str, out_asm_file.c_str(), out_ast_file.c_str());
    }
    closedir (dir);
  } else {
    std::cerr << "Error: cannot open dir" << std::endl;
    return -1;
  }
  return 0;
}

DEFINE_uint64(batch, 0, "batch size, if 0, then only one file.");
DEFINE_string(ir, "", "ir file/dir");
DEFINE_string(bin, "", "bin file/dir");
DEFINE_string(src, "", "src file/dir");
DEFINE_string(out, "", "out file/dir");
DEFINE_uint64(mode, CS_MODE_64, "cs mode"); //CS_MODE_64
DEFINE_uint64(arch, CS_ARCH_X86, "cs arch"); //CS_ARCH_X86
DEFINE_bool(withop, true, "output with or without operands");

int main(int argc, char *argv[]) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  cs_mode mode = static_cast<cs_mode>(FLAGS_mode);
  cs_arch arch = static_cast<cs_arch>(FLAGS_arch);
  if (FLAGS_batch == 1){
    std::vector<std::string> asm_str, ast_str;
    pair((char*)(FLAGS_ir.c_str()), (char*)(FLAGS_bin.c_str()), (char*)(FLAGS_src.c_str()), mode, arch, asm_str, ast_str, FLAGS_withop);
    std::string out_asm_file = FLAGS_out + "/" + "test.asm.txt";
    std::string out_ast_file = FLAGS_out+ "/" + "test.ast.txt";
    writeData(asm_str, ast_str, out_asm_file.c_str(), out_ast_file.c_str());
  }
  else if(FLAGS_batch > 1){
    batch_preprocess((char*)(FLAGS_bin.c_str()), (char*)(FLAGS_ir.c_str()), (char*)(FLAGS_src.c_str()), (char*)(FLAGS_out.c_str()), mode, arch, FLAGS_withop);
  } else {
    std::cerr << "Error: batch size must be greater than 0" << std::endl;
    return -1;
  }
  return 1;
}