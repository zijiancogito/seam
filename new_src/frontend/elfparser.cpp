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
#define FAIL 1

#define ELF_PARSE_SUCCESS 0

typedef std::optional<gtirb::Addr> INSADDR;
typedef std::pair<std::optional<gtirb::Addr>, std::optional<gtirb::Addr>> DEBUG_RANGE;
typedef struct {
	std::string filename;
	int line;
	ADDR addr;
} debug_line;

int loadELF(std::string filename) {
	FILE *fp;
	Elf64_Ehdr elf_header;
	fp = fopen(filename.c_str(), "r");
	assert(fp != NULL);
	
	int readfile = fread(&elf_header, sizeof(Elf64_Ehdr), 1, fp);
	assert(readfile != 0);
	
	if(elf_header.e_ident[0] == 0x7F || elf_header.e_ident[1] == 'E') {
		int shnum, temp;
		Elf64_Shdr *shdr = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr) * elf_header.e_shnum);
		temp = fseek(fp, elf_header.e_shoff, SEEL_SET);
		temp = fread(shdr, sizeof(Elf64_Shdr) * elf_header.e_shnum, 1, fp);
		rewind(fp);
		fseek(fp, shdr[elf_header.e_shstrndx].sh_offset, SEEK_SET);
		char shstrtab[shdr[elf_header.e_shstrndx].sh_size];
		char *names = shstrtab;
		temp = fread(shstrtab, shdr[elf_header.e_shstrndx].sh_size, 1, fp);
		for (shnum = 0; shnum < elf_header.e_shnum; shnum++ ) {
			names = shstrtab;
			names = names + shdr[shnum].sh_name;
			printf("%s\n", name);
		}	
			

	}
	return ELF_PARSE_SUCCESS;
}


int getDebugLineFromReadelf(std::string & filename) {
	std::string cmd = "readelf --debug-dump=decodedline " + filename;
	FILE *fp = popen(cmd.c_str(), "r")
	assert(fp != NULL);

	std::string buffer;
	char tmp;
	int temp = fread(&tmp, 1, 1, fp);
	while(temp != 0){
		buffer.push_back(tmp);
		temp = fread(&tmp, 1, 1, fp);
	}
	
	std::regex debug_pat("([\\S]+)[\\s]+([0-9]+)[\\s]+(0x[0-9a-f]+)[\\s]+[^\\n]+");
	std::string::const_iterator start = buffer.begin();
	std::string::const_iterator end = buffer.end();
	std::smatch match;
	int flag = FAIL;
	
	std::vector<debug_line> debugs;
	while (std::regex_search(start, end, match, debug_pat)) {
		std::string srcfile = match[1];
		int line_num = std::stoi(match[2]);
		std::string addr_str = match[3];
		start = match[0].second;
		INSADDR addr(strtoll(addr_str.c_str(), NULL, 16));
		debug_line g;
		g.filename = srcfile;
		g.line = line_num;
		g.addr = addr;
		debugs.push_back(g);
		flag = SUCCESS;
	}

	for (std::vector<debug_line>::iterator s = debugs.begin(); s!= debugs.end(); ++s) {
		if (s + 1 != debugs.end()){
			this->line2insrange[s->filename][s->line].push_back(DEBUG_RANGE(s->addr, (s+1)->addr));
		} else {
			this->line2insrange[s->filename][s->line].push_back(DEBUG_RANGE(s->addr, s->addr));
		}
	}

	return flag;
}

int main(int argc, char ** argv) {
	loadELF(argv[1]);
	return 0;
}
