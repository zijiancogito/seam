# Preprocess

## **0. ddisasm**
  ```bash
  bash ddisasm2ir.sh <binary/dir>
  ```

## **1. disasm.cpp**
  ### **class Disasm**

  **Disasm(char\*)**  param: string binary_file_name;

  **int disasm()** param: void; return: fail/success; Parse results in ir file and get Functions, CFG, BasicBlocks and Instructions. See struct definitions for more information.

  **public:**

  `binary bin;` save result of disasm();

  `std::string ir_file;` save filename of ir from **ddisasm**;

  ### **example**
  ```c++
  int main(int argc, char** argv){
    Disasm D(argv[1]);
    int ret = D.disasm();
    D.print_bin();
    return ret;
  }
  ```

## **2. binary-parser.cpp**
  ### **class ReadELF**

  **ReadELF(char\*)** param: char*;

  **int loadELF()** param: void; return: fail/succes; Load binary files and parse all sections and headers

  **void getDebugLineFromReadelf()** param: void; return: void; run command "readelf --debug-dump=decodedline" and parse output to get \<line, addr\> pair

  ### **example**
  ```c++
  int main(int argc, char* argv[]) {
    ReadELF R(argv[1]);
    // int ret = R.loadELF();
    // R.printAllSections();
    R.getDebugLineFromReadelf();
    R.printAllDebugLineInfo();
    return 0;
  }
  ```

## **3. ast.cpp**
  ### **class ASTManager**

  **ASTManager()**

  **int load(int, char\*\*)** param: count of params, params["anything", "source file", "--filter=funcname"]; return success/fail; get CompilerInstance of source code. Build AST and get all FunctionDecl in filter; At last, save all functionDecls to `this->functions`.

  **void TraverseAllFunctions()** Traverse all functions in this->functions and dump **Stmt** Node for **each line** in **Source File**

  **void TraverseFunctionAST(Decl *d, SourceManager &SM)** SM can get by `this->CI.getASTContext().getSourceManager()`; Traverse ast of function
  .

  **void RecurisiveTraverseStmt(Stmt *s, SourceManager &SM)** Traverse CompondStmts in FunctionDecl

  **void dumpStmts()** Dump Stmts in `this->line2node`.

  **void printChildStmt(Stmt *s)** Dump Stmt s.

  **example**

  ```c++
  int main(int argc, const char* argv[]){
    ASTManager a;
    a.load(argc, argv);  // 2, "anything", <source file>, --filter=<func>
    a.TraverseAllFunctions();
    llvm::outs() << "-----------------------------------------\n";
    a.dumpStmts();
    return 1;
  }
  ```

## **4. train.cpp**
  ### **pair**
  1. disasm() preprocess()
  2. loadast()
  3. loadDebug()
  4. get Line to Instructions Map from debug
  5. Map ast and asm Json based on line

# TODO
  - 在反汇编的过程中加入变量的**def-use-kill**分析，注意控制当前的数据结构，不要有大的改动，输出的格式与原来的保持一致，避免train中需要修改代码
  - AST中对节点编号进行处理，同时增加更多类型节点的分析。
