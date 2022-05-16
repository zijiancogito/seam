#include "ast.h"

using namespace clang;
using namespace llvm;

std::string ASTManager::printForTrainWithoutOperands(char* filename, int line){
  std::string ast_tmp = "";
  for (auto s : this->line2node[basename(filename)][line]) {
    stmt_analyzer sa = getStmtAnalyzer(s);
    if(sa.mnemonic != ""){
      // std::cout << sa.mnemonic << " ";
      ast_tmp += sa.mnemonic;
      ast_tmp += "";
    }
  }
  ast_tmp += "\n";
  return ast_tmp;
}

Json::Value ASTManager::printForTrainWithOperands(char* filename, int line){
  Json::Value root;
  for (auto s : this->line2node[basename(filename)][line]) {
    stmt_analyzer sa = getStmtAnalyzer(s);
    Json::Value node;
    if(sa.mnemonic != ""){
      node["mnemonic"] = sa.mnemonic;
      node["operands"] = Json::Value(Json::arrayValue);
      for(auto &op : sa.operands){
        Json::Value operand;
        operand["operand"] = op.operand;
        operand["id"] = std::to_string(op.id);
        node["operands"].append(operand);
      }
      root.append(node);
    }
  }
  return root;
}

// TODO: add more stmt class
stmt_analyzer ASTManager::getStmtAnalyzer(Stmt *s){
  stmt_analyzer ret;
  std::string name = s->getStmtClassName();
  ASTContext &context = this->CI.getASTContext();
  // llvm::outs() << ret.mnemonic << " ";
  if (isa<BinaryOperator>(s))
  {
    BinaryOperator *bop = cast<BinaryOperator>(s);
    ret.mnemonic = bop->getOpcodeStr();
    // ret.operands.push_back(bop->getOpcodeStr());
    OPERAND op1, op2, op3;
    op1.operand = name;
    op1.id = s->getID(context);
    ret.operands.push_back(op1);
    op2.operand = bop->getLHS()->getStmtClassName();
    op2.id = bop->getLHS()->getID(context);
    ret.operands.push_back(op2);
    op3.operand = bop->getRHS()->getStmtClassName();
    op3.id = bop->getRHS()->getID(context);
    ret.operands.push_back(op3);
    // llvm::outs() << ret.operands[0] << " " << ret.operands[1] << " " << ret.operands[2];
  } else if(isa<ConditionalOperator>(s))
  {
    ConditionalOperator *cop = cast<ConditionalOperator>(s);
    ret.mnemonic = name;
    OPERAND op1, op2, op3;
    op1.operand = cop->getCond()->getStmtClassName();
    op1.id = cop->getCond()->getID(context);
    ret.operands.push_back(op1);
    op2.operand = cop->getTrueExpr()->getStmtClassName();
    op2.id = cop->getTrueExpr()->getID(context);
    ret.operands.push_back(op2);
    op3.operand = cop->getFalseExpr()->getStmtClassName();
    op3.id = cop->getFalseExpr()->getID(context);
    ret.operands.push_back(op3);
  } else if(isa<UnaryOperator>(s)) {
    UnaryOperator *uop = cast<UnaryOperator>(s);
    ret.mnemonic = uop->getOpcodeStr(uop->getOpcode());
    OPERAND op1;
    op1.id = uop->getSubExpr()->getID(context);
    op1.operand = uop->getSubExpr()->getStmtClassName();
    ret.operands.push_back(op1);
  } else if(isa<ImplicitCastExpr>(s)) {
    ret.mnemonic = "";
  } else if(isa<IntegerLiteral>(s)) {
    ret.mnemonic = "";
  } else if(isa<DeclRefExpr>(s)){
    ret.mnemonic = "";
  }
  else
  {
    ret.mnemonic = name;
  }
  // llvm::outs() << "\n";
  return ret;
}

// TODO: add df analyze for block of each line
void ASTManager::df_analyze(){
  
}
// Post-order traversal
int ASTManager::getAllStmtsInLine(std::vector<Stmt*>& stmts, Stmt* root) {
  if (root == NULL) {
    return 0;
  }
  // llvm::outs() << "root: " << root->getStmtClassName() << "\n";
  for (Stmt::child_iterator start = root->child_begin(); start != root->child_end(); ++start)
  {
    getAllStmtsInLine(stmts, *start);
  }
  stmts.push_back(root);
  return 1;
}

void ASTManager::printChildStmt(Stmt *s) {
  llvm::outs() << s->getStmtClassName() << " ";
  for (Stmt::child_iterator start = s->child_begin(); start != s->child_end(); ++start)
  {
    if ((*start) != NULL){
      // llvm::outs() << start->getStmtClassName() << " ";
      getStmtAnalyzer(*start);
    }
  }
  llvm::outs() << "\n\n";
}

void ASTManager::dumpStmts(){
  for(auto i : this->line2node) {
    for (auto j : i.second) {
      for (auto k : j.second) {
        llvm::outs() << i.first << " " << j.first << "\n";
        k->dump();
        llvm::outs() << "\n";
      }
    }
  }
}

void ASTManager::RecurisiveTraverseStmt(Stmt *s, SourceManager &SM) {
  for (Stmt::child_iterator start = s->child_begin(); start != s->child_end(); ++start)
  {
    if ((*start) != NULL){
      SourceLocation begin = start->getBeginLoc();
      SourceLocation end = start->getEndLoc();
      std::string begin_loc = begin.printToString(SM);
      std::string end_loc = end.printToString(SM);
      // llvm::outs() << begin_loc << "\n";
      // printChildStmt(*start);
      std::regex loc("([\\S]+):([0-9]+):([0-9]+)");
      std::smatch begin_match, end_match;
      int b = regex_match(begin_loc, begin_match, loc);
      int e = regex_match(end_loc, end_match, loc);
      std::string bf = begin_match[1];
      std::string ef = end_match[1];
      int bl = stoi(begin_match[2]), el = stoi(end_match[2]);
      char *filename = (char*)(bf.c_str());
      if ((bf == ef) && (bl == el)) {
        // start->dump();
        // llvm::outs() << bf << " " << bl << "\n\n";
        // this->line2node[basename(filename)][bl].push_back(*start);
        this->getAllStmtsInLine(this->line2node[basename(filename)][bl], *start);
      }
      else{
        RecurisiveTraverseStmt(*start, SM);
        this->line2node[basename(filename)][bl].push_back(*start);
      }
    }
  }
  
}

void ASTManager::TraverseFunctionAST(Decl *d, SourceManager &SM) {
  if(d->hasBody()){
    Stmt *s = d->getBody();
    RecurisiveTraverseStmt(s, SM);
  }
}

void ASTManager::TraverseAllFunctions(){
  for (auto f : this->functions){
    TraverseFunctionAST(f, this->CI.getASTContext().getSourceManager());
  }
}

int ASTManager::load(int argc, const char **argv, const char *filename, const char *funcfilter) {
  llvm::cl::ParseCommandLineOptions(argc, argv, "AST Frontend\n");
  // Create a compiler instance.
  // Create the diagnostic engine.
  // static llvm::cl::OptionCategory ToolingSampleCategory("Tooling Sample");
  // static cl::extrahelp CommonHelp(clang::tooling::CommonOptionsParser::HelpMessage);
  // static cl::extrahelp MoreHelp("No more help");
  // clang::tooling::CommonOptionsParser op(argc, argv, ToolingSampleCategory);
  // ClangTool Tool(op.getCompilations(), op.getSourcePathList());

  DiagnosticOptions diagnosticOptions;
  CI.createDiagnostics();

  std::shared_ptr<clang::TargetOptions> PTO =
        std::shared_ptr<clang::TargetOptions>(new clang::TargetOptions());
  PTO->Triple = llvm::sys::getDefaultTargetTriple();
  clang::TargetInfo *PTI = clang::TargetInfo::CreateTargetInfo(CI.getDiagnostics(), PTO);

  CI.setTarget(PTI);
  CI.createFileManager();
  CI.createSourceManager(CI.getFileManager());
  CI.createPreprocessor(TU_Complete);
  // (CI.getPreprocessorOpts()).UsePredefines = false;
  std::unique_ptr<ASTConsumer> astConsumer = CreateASTPrinter(NULL, "");
  CI.setASTConsumer(std::move(astConsumer));

  CI.createASTContext();
  CI.createSema(TU_Complete, NULL);
  auto pFileErr = std::move(CI.getFileManager().getFile(filename));
  assert(pFileErr && "Couldn't open input file.");
  this->source_filename = filename;
  const FileEntry *pFile = pFileErr.get();

  FileID fid = CI.getSourceManager().createFileID(pFile, SourceLocation(), SrcMgr::C_User);
  CI.getSourceManager().setMainFileID(fid);
  CI.getDiagnosticClient().BeginSourceFile(CI.getLangOpts(), 0);
  ParseAST(CI.getSema());
  // Print AST statistics
  // CI.getASTContext().PrintStats();
  ASTContext &Context = CI.getASTContext();
  SourceManager &SM = Context.getSourceManager();

  TranslationUnitDecl *TU =  Context.getTranslationUnitDecl();
  // TU->dump();
  for (DeclContext::decl_iterator start = TU->decls_begin(); start != TU->decls_end(); ++start)
  {
    if (strcmp(start->getDeclKindName(), "Function") == 0)
    {
      const NamedDecl *ND = dyn_cast<NamedDecl>(*start);
      if (ND)
      {
        if(funcfilter != ""){
          if (strcmp(ND->getQualifiedNameAsString().c_str(), funcfilter) == 0)
          {
            //TraverseFunctionAST(*start, SM);
            this->functions.push_back(*start);
            break;
          }
        }
        else{
          //TraverseFunctionAST(*start, SM);
          this->functions.push_back(*start);
        }
      }
    }
  }
  return LOAD_SUCCESS;
}


int main(int argc, const char* argv[]){
  ASTManager a;
  a.load(argc, argv, "/home/caoy/re_proj/seam/dataset/re/csmith/src/random8000.c", "func_1");
  a.TraverseAllFunctions();
  llvm::outs() << "-----------------------------------------\n";
  a.dumpStmts();
  return 1;
}