#!/bin/bash

disasm(){
  echo "Disassembling $1"
  ddisasm $1 --ir $2
  echo "Saving IR to $2"
}

if [ $# -eq 0 ]; then
  echo "Usage: $0 <file> [<file> ...]"
  exit 1
elif [ -d "$1" ]; then
  mkdir -p $1/ddisasm_ir
  for file in `ls $1/gcc94/`; do
    disasm $1/gcc94/$file $1/ddisasm_ir/$file.ir
  done
elif [ -f "$1" ]; then
      disasm $1 $1.ir
else
  echo "Usage: $0 <file> [<file> ...]"
  exit 1
fi