#include "binary-parser.h"


// g++ -std=c++17 -I ./ binary-parser.cpp -lgtirb -shared -fPIC -o libbinary-parser.so

int ReadELF::loadELF() {
  FILE *fp;
  Elf64_Ehdr elf_header;

  fp = fopen(filename.c_str(), "r");
  assert(fp != NULL);
  int readfile = fread(&elf_header, sizeof(Elf64_Ehdr), 1, fp);
  assert(readfile != 0);
  if (elf_header.e_ident[0] == 0x7F || elf_header.e_ident[1] == 'E') {
    // TODO: load others

    // load sections
    int shnum, temp;
    Elf64_Shdr *shdr = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr) * elf_header.e_shnum);
    temp = fseek(fp, elf_header.e_shoff, SEEK_SET);
    temp = fread(shdr, sizeof(Elf64_Shdr) * elf_header.e_shnum, 1, fp);
    rewind(fp);
    fseek(fp, shdr[elf_header.e_shstrndx].sh_offset, SEEK_SET);
    char shstrtab[shdr[elf_header.e_shstrndx].sh_size];
    char *names = shstrtab;
    temp = fread(shstrtab, shdr[elf_header.e_shstrndx].sh_size, 1, fp);
    for (shnum = 0; shnum < elf_header.e_shnum; shnum++){
      names = shstrtab;
      names = names+shdr[shnum].sh_name;
      this->sections[names] = shdr[shnum];
      // printf("%x\t%x\t%x\t%x\t%s \n",
      //         shdr[shnum].sh_type,
      //         shdr[shnum].sh_addr,
      //         shdr[shnum].sh_offset,
      //         shdr[shnum].sh_size,
      //         names);
    }
    return SUCCESS;
  }
  return FAILURE;
}

void ReadELF::printAllSections(){
  for(auto i : this->sections) {
    printf("%x\t%x\t%x\t%x\t%s \n",
              i.second.sh_type,
              i.second.sh_addr,
              i.second.sh_offset,
              i.second.sh_size,
              i.first.c_str());
  }
}

bool ReadELF::in(ADDR addr, std::vector<ADDR_RANGE> range) {
  int flag = false;
  for(auto i : range) {
    if(addr >= i.first && addr < i.second) {
      flag = true;
      break;
    }
  }
  return flag;
}

int ReadELF::findLine(ADDR addr){
  for(auto &f : this->line2insrange) {
    for(auto &l : f.second) {
      if(in(addr, l.second)) {
        return l.first;
      }
    }
  }
  return -1;
}

int ReadELF::getDebugLineFromReadelf(){
  std::string cmd = "readelf --debug-dump=decodedline " + this->filename;
  FILE *fp = popen(cmd.c_str(), "r");
  assert(fp != NULL);
  // std::regex info_header("File name[\\s]*Line number[\\s]*Starting address[\\s]*View[\\s]*Stmt\\n");
  std::string buffer;
  char tmp;
  int temp = fread(&tmp, 1, 1, fp);
  while(temp != 0){
    buffer.push_back(tmp);
    temp = fread(&tmp, 1, 1, fp);
  }
  // std::cout << buffer << std::endl;
  std::regex debug_pat("([\\S]+)[\\s]+([0-9]+)[\\s]+(0x[0-9a-f]+)[\\s]+[^\\n]+");
  std::string::const_iterator start = buffer.begin();
  std::string::const_iterator end = buffer.end();
  std::smatch match;
  int flag = FAILURE;

  std::vector<debug_line> debugs;
  while (std::regex_search(start, end, match, debug_pat))
  {
    std::string source_file = match[1];
    int line_num = std::stoi(match[2]);
    std::string addr_s = match[3];
    start = match[0].second;
    std::optional<gtirb::Addr> addr(strtoll(addr_s.c_str(), NULL, 16));
    // this->insaddr2line[ad] = std::make_tuple(source_file, line_num);
    debug_line g;
    g.filename = source_file;
    g.line = line_num;
    g.addr = addr;
    // std::cout << "filename: " << source_file << " line: " << line_num << " addr: " << addr_s << std::endl;
    debugs.push_back(g);
    flag = SUCCESS;
  }
  for (std::vector<debug_line>::iterator s = debugs.begin(); s != debugs.end(); ++s) {
    if(s+1 != debugs.end()){
      this->line2insrange[s->filename][s->line].push_back(ADDR_RANGE(s->addr, (s+1)->addr));
    } else {
      // NOTE: the last instruction range begin == end
      this->line2insrange[s->filename][s->line].push_back(ADDR_RANGE(s->addr, s->addr));
    }
  }
  return flag;
}


int main(int argc, char* argv[]) {
  ReadELF R(argv[1]);
  // int ret = R.loadELF();
  // R.printAllSections();
  int ret = R.getDebugLineFromReadelf();
  return 0;
}
