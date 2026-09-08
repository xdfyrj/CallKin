"""Read retained ELF functions and locate source-specific error-message references."""
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_MEM, X86_OP_IMM, X86_REG_RIP

HERE=Path(__file__).resolve().parent
ROOT=Path(json.loads((HERE/'inputs.json').read_text())['input_root'])
CASES={
 'zoxide': {'FUN_00191360':('invalid utf-8',42),'FUN_00191460':('invalid rank',48),'FUN_001915a0':('invalid entry',45)},
 'fd': {'FUN_0027a400':('Malformed exclude pattern',339),'FUN_0027a470':('Mismatch in exclude patterns',344)},
}


def verify():
    output={}
    for case, functions in CASES.items():
        path=ROOT/f'gt_bin/plain/{case}.O3S.gt.bin'
        build=json.loads((ROOT/f'build_info/plain/{case}.O3S.json').read_text())
        digest=hashlib.sha256(path.read_bytes()).hexdigest()
        if digest!=build['artifacts']['non_stripped']['sha256']:
            raise ValueError('ELF does not match retained build')
        with path.open('rb') as f:
            elf=ELFFile(f)
            segments=[(s['p_vaddr'],s.data()) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
            symbols=list(elf.get_section_by_name('.symtab').iter_symbols())
            def memory(address,length):
                for base,data in segments:
                    if base<=address<base+len(data):return data[address-base:address-base+length]
                return b''
            decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
            rows=[]
            for fid,(needle,line) in functions.items():
                address=int(fid[4:],16)-0x100000
                matches=[s for s in symbols if s['st_value']==address and s['st_info']['type']=='STT_FUNC']
                if not matches:raise ValueError(f'missing symbol {fid}')
                size=max(s['st_size'] for s in matches)
                refs=set()
                calls=set()
                for ins in decoder.disasm(memory(address,size),address):
                    if ins.mnemonic=='call' and ins.operands and ins.operands[0].type==X86_OP_IMM:
                        calls.add(ins.operands[0].imm)
                    for operand in ins.operands:
                        if operand.type==X86_OP_MEM and operand.mem.base==X86_REG_RIP:
                            refs.add(ins.address+ins.size+operand.mem.disp)
                hits=[]
                for ref in refs:
                    data=memory(ref,80)
                    if needle.encode() in data:hits.append({'via':'direct-rip','address':hex(ref)})
                    for offset in range(0,min(len(data),64)-7,8):
                        target=int.from_bytes(data[offset:offset+8],'little')
                        if needle.encode() in memory(target,80):
                            hits.append({'via':'rip-data-pointer','address':hex(target),'descriptor':hex(ref)})
                if not hits:
                    # A formatting specialization can own the literal: inspect only direct, small callees.
                    for callee in sorted(calls):
                        sizes=[s['st_size'] for s in symbols if s['st_value']==callee and s['st_info']['type']=='STT_FUNC']
                        if not sizes or max(sizes)>2048:continue
                        for ins in decoder.disasm(memory(callee,max(sizes)),callee):
                            for operand in ins.operands:
                                if operand.type==X86_OP_MEM and operand.mem.base==X86_REG_RIP:
                                    ref=ins.address+ins.size+operand.mem.disp
                                    if needle.encode() in memory(ref,80):
                                        hits.append({'via':'direct-helper-rip','helper':hex(callee),'address':hex(ref)})
                if not hits:raise ValueError(f'{fid}: expected source-specific message not reached')
                rows.append({'member':fid,'elf_address':hex(address),'size':size,'raw_symbols':[s.name for s in matches],
                    'source_line':line,'expected_message':needle,'message_references':hits})
            output[case]={'binary_sha256':digest,'members':rows}
    (HERE/'closure-site-check.json').write_text(json.dumps(output,indent=2)+'\n')
    print('Five closure bodies independently checked against distinct source-specific message references.')


if __name__=='__main__':verify()
