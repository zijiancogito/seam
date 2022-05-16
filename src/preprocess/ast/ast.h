#include "llvm/ADT/IntrusiveRefCntPtr.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Host.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclBase.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/DiagnosticOptions.h"
#include "clang/Basic/FileManager.h"
#include "clang/Basic/LangOptions.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Basic/TargetOptions.h"
#include "clang/Frontend/ASTConsumers.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/TextDiagnosticPrinter.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Parse/Parser.h"
#include "clang/Parse/ParseAST.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"

#include <iostream>
#include <vector>
#include <regex>
#include <libgen.h>
#include <jsoncpp/json/json.h>

#define LOAD_SUCCESS 0
#define LOAD_FAIL 1
using namespace clang;
using namespace llvm;
// static cl::opt<std::string> FileName(cl::Positional, cl::desc("input file"), cl::Required);
// static cl::opt<std::string> FuncFilter("funcfilter", cl::desc("function filter"));

typedef struct {
  std::string operand;
  int64_t id;
} OPERAND;

typedef struct {
  std::string mnemonic;
  std::vector<OPERAND> operands;
} stmt_analyzer;

class ASTManager
{

private:
  
public:
  std::string source_filename;
  CompilerInstance CI;
  std::vector<clang::Decl *> functions;
  std::map<std::string, std::map<int, std::vector<clang::Stmt *>>> line2node;

public:
  ASTManager()
  {
  }
  ~ASTManager(){}

  //TODO: parse list filter
  int load(int argc, const char **argv, const char *filename, const char *funcfilter);
  void TraverseAllFunctions();
  void TraverseFunctionAST(Decl *d, SourceManager &SM);
  void RecurisiveTraverseStmt(Stmt *s, SourceManager &SM);
  void printChildStmt(Stmt *s);
  void dumpStmts();

  stmt_analyzer getStmtAnalyzer(Stmt*);
  int getAllStmtsInLine(std::vector<Stmt*>& stmts, Stmt* root);

  Json::Value printForTrainWithOperands(char* filename, int line);
  std::string printForTrainWithoutOperands(char* filename, int line);
  void df_analyze();
};