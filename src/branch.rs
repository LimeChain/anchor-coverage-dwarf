use addr2line::{
    fallible_iterator::FallibleIterator,
    gimli::{self, ReaderOffset},
    Frame,
};
use anyhow::{anyhow, Result};
use solana_sbpf::ebpf;
use std::{collections::BTreeMap, fs::OpenOptions, path::Path};

use crate::{vaddr::Vaddr, Dwarf, Insns, Regs, Vaddrs};

const PRINT_DEBUG: bool = false;
const fn debug_enabled() -> bool {
    PRINT_DEBUG
}

type Branches = BTreeMap<Vaddr, Branch>;

#[allow(dead_code)]
fn get_indent(indent: i32) -> String {
    let mut s = String::new();
    (0..indent).into_iter().for_each(|_| s.push_str("\t"));
    s
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct FrameDetails<'a> {
    dw_die_offset: Option<u64>,
    demangled_function_name: Option<String>,
    file_name: Option<&'a str>,
    line_num: Option<u32>,
    column: Option<u32>,
}

fn get_frame_details<'a, R: gimli::Reader>(frame: &Frame<'a, R>) -> FrameDetails<'a> {
    let dw_die_offset = frame
        .dw_die_offset
        .map(|inner| Some(inner.0.into_u64()))
        .unwrap_or(None);
    let demangled_function_name = frame.function.as_ref().map(|inner| {
        inner
            .demangle()
            .unwrap_or("cant_demangle".into())
            .to_string()
    });
    let file_name = frame
        .location
        .as_ref()
        .map(|inner| inner.file)
        .unwrap_or(None);
    let line_num = frame
        .location
        .as_ref()
        .map(|inner| inner.line)
        .unwrap_or(None);
    let column = frame
        .location
        .as_ref()
        .map(|inner| inner.column)
        .unwrap_or(None);
    FrameDetails {
        dw_die_offset,
        demangled_function_name,
        file_name,
        line_num,
        column,
    }
}

#[derive(PartialEq, Clone, Default, Debug)]
pub struct Branch {
    pub file: Option<String>,
    pub line: Option<u32>,
    pub next_taken: u32,
    pub goto_taken: u32,
    pub branch_id: u64,
}

impl Branch {
    pub fn new(file: Option<&str>, line: Option<u32>, branch_id: u64) -> Self {
        Self {
            file: file.map(|inner| inner.to_string()),
            line,
            branch_id,
            ..Default::default()
        }
    }
}

#[derive(PartialEq, Clone)]
pub enum LcovBranch {
    NextNotTaken,
    GotoNotTaken,
}

fn write_branch_lcov<W: std::io::Write>(
    lcov_file: &mut W,
    file: &str,
    line: u32,
    _taken: LcovBranch,
    _branch_id: u64,
) -> Result<usize, std::io::Error> {
    let content = if _taken == LcovBranch::NextNotTaken
    /* true */
    {
        format!(
            "
SF:{file}
DA:{line},1
BRDA:{line},{_branch_id},0,0
BRDA:{line},{_branch_id},1,1
end_of_record
"
        )
    } else {
        format!(
            "
SF:{file}
DA:{line},1
BRDA:{line},{_branch_id},0,1
BRDA:{line},{_branch_id},1,0
end_of_record
"
        )
    };

    lcov_file.write(content.as_bytes())
}

#[allow(dead_code)]
fn get_frame_details_by_vaddr<'a>(dwarf: &Dwarf, vaddr: u64) -> Option<FrameDetails<'a>> {
    let mut frame = dwarf.loader.find_frames(vaddr).ok()?;
    let frame = frame.next().ok()??;
    let frame_details = get_frame_details(&frame);
    Some(frame_details)
}

pub fn get_branches(
    vaddrs: &Vaddrs,
    insns: &Insns,
    regs: &Regs,
    dwarf: &Dwarf,
) -> Result<Branches, anyhow::Error> {
    let text_section_offset = dwarf
        .loader
        .get_section_range(b".text")
        .ok_or(anyhow!("Can't get .text section begin address"))?
        .begin;

    let mut branches = Branches::new();
    let mut branches_total_count = 0;
    for (i, vaddr) in vaddrs.iter().enumerate() {
        let mut _indent = 0;
        let frames = dwarf.loader.find_frames(*vaddr);
        if let Ok(frames) = frames {
            let mut frames = frames.peekable();
            while let Some(Some(frame)) = frames.next().ok() {
                _indent += 1;
                let outer_frame_details = get_frame_details(&frame);
                if debug_enabled() {
                    eprintln!(
                            "{}⛳ 0x{:08x}({}) [{:016x}]=> frame 0x{:08x?}#{:?}@{:?}:{:?}:{:?}\n{}VM regs: {:08x?}\n",
                            get_indent(_indent-1),
                            *vaddr,
                            vaddr >> 3,
                            insns[i],
                            outer_frame_details.dw_die_offset,
                            outer_frame_details.demangled_function_name,
                            outer_frame_details.file_name,
                            outer_frame_details.line_num,
                            outer_frame_details.column,
                            get_indent(_indent),
                            regs[i],
                        );
                }

                let ins = insns[i].to_be_bytes();
                // eprintln!("{:02x?}", ins);

                let ins_type = ins[0];
                // let ins_dst = (ins[1] & 0xf) as usize;
                // let ins_src = ((ins[1] & 0xf0) >> 4) as usize;
                let ins_offset = ins[2] as u64 | ((ins[3] as u64) << 8);
                // let ins_immediate = i32::from_be_bytes(ins[4..].try_into().unwrap()) as i64;
                if (ins_type & ebpf::BPF_JMP) == ebpf::BPF_JMP {
                    let _next_pc = vaddr + 8;
                    if debug_enabled() {
                        eprintln!("very next instruction is: {:x}", _next_pc);
                    }
                    let goto_pc = vaddr + ins_offset * 8 + 8;

                    // get next_pc from the next batch of registers corresponding to the next vaddr.
                    if debug_enabled() {
                        eprintln!("current regs: {:x?}", regs[i]);
                        if regs.get(i + 1).is_some() {
                            eprintln!("next regs: {:x?}", regs[i + 1]);
                        }
                    }
                    let Some(Some(mut next_pc)) =
                        regs.get(i + 1).map(|regs| regs[11].checked_shl(3))
                    else {
                        continue;
                    };

                    // procdump: the PCs need to be shifted with regards to the text section offset.
                    next_pc += text_section_offset;
                    if debug_enabled() {
                        eprintln!(
                            "goto_pc calced from vaddr: {:x}, ins_offset: {}",
                            goto_pc, ins_offset
                        );
                        eprintln!("from next regs -> next_pc is: {:x}", next_pc);
                    }

                    match ins_type {
                        // ebpf::JA
                        ebpf::JEQ_IMM
                        | ebpf::JEQ_REG
                        | ebpf::JGT_IMM
                        | ebpf::JGT_REG
                        | ebpf::JGE_IMM
                        | ebpf::JGE_REG
                        | ebpf::JLT_IMM
                        | ebpf::JLT_REG
                        | ebpf::JLE_IMM
                        | ebpf::JLE_REG
                        | ebpf::JSET_IMM
                        | ebpf::JSET_REG
                        | ebpf::JNE_IMM
                        | ebpf::JNE_REG
                        | ebpf::JSGT_IMM
                        | ebpf::JSGT_REG
                        | ebpf::JSGE_IMM
                        | ebpf::JSGE_REG
                        | ebpf::JSLT_IMM
                        | ebpf::JSLT_REG
                        | ebpf::JSLE_IMM
                        | ebpf::JSLE_REG
                        // | ebpf::CALL_REG
                        // | ebpf::CALL_IMM
                        // | ebpf::SYSCALL
                        // | ebpf::RETURN /*| ebpf::EXIT */
                        => {},
                        _ => {
                            continue;
                        }
                    };

                    // // Skip Rust closures
                    // if let Some(demangled_fn_name) = &outer_frame_details.demangled_function_name {
                    //     if demangled_fn_name.contains(r#"{{closure}}"#) {
                    //         continue;
                    //     }
                    // }

                    // There's a branch at this vaddr.
                    let branch = branches.entry(Vaddr::from(*vaddr)).or_insert({
                        branches_total_count += 1;
                        let branch_id = branches_total_count;
                        Branch::new(
                            outer_frame_details.file_name, // TODO: if these are None? Update them later?
                            outer_frame_details.line_num,
                            branch_id,
                        )
                    });
                    if next_pc == goto_pc {
                        if goto_pc == (*vaddr + 8) {
                            // The case when the goto is exactly the next instruction.
                            branch.next_taken += 1;
                            branch.goto_taken += 1;
                        } else {
                            branch.goto_taken += 1;
                        }
                    } else {
                        branch.next_taken += 1;
                    };
                }
                break; // only interested in the first frame deep, inners are just stack frames and we don't have the regs snapshots
            }
        }
    }
    Ok(branches)
}

pub fn write_branch_coverage(branches: &Branches, pcs_path: &Path) -> Result<()> {
    let path = pcs_path
        .parent()
        .and_then(|p| p.parent())
        .ok_or(anyhow!("Can't get to root of the project"))?
        .join("programs");

    let programs: Vec<_> = std::fs::read_dir(&path)?
        .map(|e| e.map(|e| e.file_name().display().to_string()))
        .collect::<Result<Vec<_>, _>>()?;

    let sbf_trace_dir = std::env::var("SBF_TRACE_DIR").unwrap_or("sbf_trace_dir".into());
    let mut lcov_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(format!("{}/branches.lcov", sbf_trace_dir))
        .expect("cannot open file");

    for (_vaddr, branch) in branches {
        match (&branch.file, branch.line) {
            (Some(file), Some(line)) => {
                if programs
                    .iter()
                    .filter(|e| file.contains(*e))
                    .nth(0)
                    .is_none()
                {
                    continue;
                }

                if branch.goto_taken != 0 && branch.next_taken != 0 {
                    // // Both hit. So add them.
                    write_branch_lcov(
                        &mut lcov_file,
                        &file,
                        line,
                        LcovBranch::NextNotTaken,
                        branch.branch_id,
                    )?;
                    write_branch_lcov(
                        &mut lcov_file,
                        &file,
                        line,
                        LcovBranch::GotoNotTaken,
                        branch.branch_id,
                    )?;
                    // continue;
                } else {
                    // Only one branch hit, act accordingly.
                    write_branch_lcov(
                        &mut lcov_file,
                        &file,
                        line,
                        if branch.next_taken == 0 {
                            LcovBranch::GotoNotTaken
                        } else {
                            LcovBranch::NextNotTaken
                        },
                        branch.branch_id,
                    )?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}
