#!/usr/bin/env python3

import sys, os

if len(sys.argv) != 3:
  print("Usage: python3 modify_java_core.py <hs_err_pid.log> <corefile>")
  sys.exit(0)

hs_file = sys.argv[1]
core = sys.argv[2]

registers = { }

fp = open(hs_file, "r")

in_registers= False

for line in fp:
  if "tid=" in line:
    line = line[line.find("tid="):].split(",")[0].strip()
    tid = line.split("=")[1].strip()
    print(tid)
    continue

  if line.startswith("Registers:"):
    in_registers = True
    continue

  if not in_registers: continue
  line = line.strip()
  if line == "": break

  tokens = line.split(",")

  for token in tokens:
    (register, value) = token.split("=")
    registers[register.strip()] = value.strip()

fp.close()

#os.system("cp " + core + " " + core + ".modified")

for register in registers:
  # FIXME: Should probably add these other registers to the list.
  if register in [ "EFLAGS", "CSGSFS", "ERR", "TRAPNO" ]: continue

  value = registers[register]
  register = register.lower()
  #print(register + " " + registers[register])

  #os.system("magic_elf -modify_core " + tid + " " + register + " " + value + " " + core + ".modified")
  print("magic_elf -modify_core " + tid + " " + register + " " + value + " " + core + ".modified")

