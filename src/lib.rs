use addr2line::{
    fallible_iterator::FallibleIterator,
    gimli::{self, ReaderOffset},
    Frame, Loader,
};
use anyhow::{anyhow, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use cargo_metadata::MetadataCommand;
use solana_sbpf::ebpf;
use std::{
    collections::BTreeMap,
    env::var_os,
    fs::{metadata, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub const DOCKER_BUILDER_VERSION: &str = "0.0.0";

#[cfg(feature = "__anchor_cli")]
mod anchor_cli_lib;
#[cfg(feature = "__anchor_cli")]
pub use anchor_cli_lib::__build_with_debug;
#[cfg(feature = "__anchor_cli")]
pub use anchor_cli_lib::{
    __get_keypair as get_keypair, __is_hidden as is_hidden, __keys_sync as keys_sync,
};

#[cfg(feature = "__anchor_cli")]
mod anchor_cli_config;
#[cfg(feature = "__anchor_cli")]
use anchor_cli_config as config;
#[cfg(feature = "__anchor_cli")]
pub use anchor_cli_config::{BootstrapMode, ConfigOverride, ProgramArch};

mod insn;
use insn::Insn;

mod start_address;
use start_address::start_address;

pub mod util;
use util::{files_with_extension, StripCurrentDir};

mod vaddr;
use vaddr::Vaddr;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Entry<'a> {
    file: &'a str,
    line: u32,
}

struct Dwarf {
    path: PathBuf,
    start_address: u64,
    #[allow(dead_code, reason = "`vaddr` points into `loader`")]
    loader: &'static Loader,
    vaddr_entry_map: BTreeMap<u64, Entry<'static>>,
}

enum Outcome {
    Lcov(PathBuf),
    ClosestMatch(PathBuf),
}

type Vaddrs = Vec<u64>;
type Insns = Vec<u64>;
type Regs = Vec<[u64; 12]>;

type VaddrEntryMap<'a> = BTreeMap<u64, Entry<'a>>;

#[allow(dead_code)]
#[derive(Debug)]
struct ClosestMatch<'a, 'b> {
    pcs_path: &'a Path,
    debug_path: &'b Path,
    mismatch: Mismatch,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default)]
struct Mismatch {
    index: usize,
    vaddr: Vaddr,
    expected: Insn,
    actual: Insn,
}

type FileLineCountMap<'a> = BTreeMap<&'a str, BTreeMap<u32, usize>>;

pub fn run(sbf_trace_dir: impl AsRef<Path>, debug: bool) -> Result<()> {
    let mut lcov_paths = Vec::new();
    let mut closest_match_paths = Vec::new();

    let debug_paths = debug_paths()?;

    let dwarfs = debug_paths
        .into_iter()
        .map(|path| build_dwarf(&path))
        .collect::<Result<Vec<_>>>()?;

    if dwarfs.is_empty() {
        eprintln!("Found no debug files");
        return Ok(());
    }

    if debug {
        for dwarf in dwarfs {
            dump_vaddr_entry_map(dwarf.vaddr_entry_map);
        }
        return Ok(());
    }

    let pcs_paths = files_with_extension(&sbf_trace_dir, "pcs")?;

    for pcs_path in &pcs_paths {
        match process_pcs_path(&dwarfs, pcs_path)? {
            Outcome::Lcov(lcov_path) => {
                lcov_paths.push(lcov_path.strip_current_dir().to_path_buf());
            }
            Outcome::ClosestMatch(closest_match_path) => {
                closest_match_paths.push(closest_match_path.strip_current_dir().to_path_buf());
            }
        }
    }

    eprintln!(
        "
Processed {} of {} program counter files

Lcov files written: {lcov_paths:#?}

Closest match files written: {closest_match_paths:#?}

If you are done generating lcov files, try running:

    genhtml --output-directory coverage {}/*.lcov --rc branch_coverage=1 && open coverage/index.html
",
        lcov_paths.len(),
        pcs_paths.len(),
        sbf_trace_dir.as_ref().strip_current_dir().display()
    );

    Ok(())
}

fn debug_paths() -> Result<Vec<PathBuf>> {
    let metadata = MetadataCommand::new().no_deps().exec()?;
    let target_directory = metadata.target_directory;
    files_with_extension(target_directory.join("deploy"), "debug")
}

fn build_dwarf(debug_path: &Path) -> Result<Dwarf> {
    let start_address = start_address(debug_path)?;

    let loader = Loader::new(debug_path).map_err(|error| {
        anyhow!(
            "failed to build loader for {}: {}",
            debug_path.display(),
            error.to_string()
        )
    })?;

    let loader = Box::leak(Box::new(loader));

    let vaddr_entry_map = build_vaddr_entry_map(loader, debug_path)?;

    Ok(Dwarf {
        path: debug_path.to_path_buf(),
        start_address,
        loader,
        vaddr_entry_map,
    })
}

fn process_pcs_path(dwarfs: &[Dwarf], pcs_path: &Path) -> Result<Outcome> {
    eprintln!();
    eprintln!(
        "Program counters file: {}",
        pcs_path.strip_current_dir().display()
    );

    let (mut vaddrs, insns, regs) = read_vaddrs(pcs_path)?;
    for va in vaddrs.iter() {
        eprintln!(
            "\t\t\t {:x} from {}",
            *va,
            pcs_path.to_string_lossy().to_string()
        );
    }
    eprintln!("Program counters read: {}", vaddrs.len());

    let (dwarf, mismatch) = find_applicable_dwarf(dwarfs, pcs_path, &mut vaddrs)?;

    if let Some(mismatch) = mismatch {
        return write_closest_match(pcs_path, dwarf, mismatch).map(Outcome::ClosestMatch);
    }

    eprintln!(
        "Applicable dwarf: {}",
        dwarf.path.strip_current_dir().display()
    );

    // assert!(vaddrs
    //     .first()
    //     .is_some_and(|&vaddr| vaddr == dwarf.start_address));

    // smoelius: If a sequence of program counters refer to the same file and line, treat them as
    // one hit to that file and line.
    // vaddrs.dedup_by_key::<_, Option<&Entry>>(|vaddr| dwarf.vaddr_entry_map.get(vaddr));

    // eprintln!("find_symbol: {:?}", dwarf.loader.find_symbol(0x8d60));
    // let range = dwarf.loader.find_location_range(0x8d58, 0x8d70);
    // if let Ok(mut range_iter) = range {
    //     while let Some((a, b, c)) = range_iter.next() {
    //         eprintln!("{:08x?} {:08x?} {:?} {:?}", a, b, c.file, c.line);
    //     }
    // }

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

    #[derive(PartialEq)]
    pub enum Branch {
        NextNotTaken,
        GotoNotTaken,
    }

    fn write_branch_lcov(file: &str, line: u32, taken: Branch) {
        let content = if taken == Branch::NextNotTaken {
            format!(
                "
SF:{file}
DA:{line},1
BRDA:{line},0,0,0
BRDA:{line},0,1,1
end_of_record
"
            )
        } else {
            format!(
                "
SF:{file}
DA:{line},1
BRDA:{line},0,0,1
BRDA:{line},0,1,0
end_of_record
"
            )
        };
        let mut lcov_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!("sbf_trace_dir/1.lcov"))
            .expect("cannot open file");
        if file.contains("vault") {
            let _ = lcov_file.write_all(content.as_bytes());
        }
    }

    fn get_frame_details_by_vaddr<'a>(dwarf: &Dwarf, vaddr: u64) -> Option<FrameDetails<'a>> {
        let mut frame = dwarf.loader.find_frames(vaddr).ok()?;
        let frame = frame.next().ok()??;
        let frame_details = get_frame_details(&frame);
        Some(frame_details)
    }

    for (i, vaddr) in vaddrs.iter().enumerate() {
        let mut indent = 0;
        let frames = dwarf.loader.find_frames(*vaddr);
        if let Ok(frames) = frames {
            let mut frames = frames.peekable();
            while let Some(Some(frame)) = frames.next().ok() {
                indent += 1;
                let frame_details = get_frame_details(&frame);
                eprintln!(
                            "{}⛳ 0x{:08x}({}) [{:016x}]=> frame 0x{:08x?}#{:?}@{:?}:{:?}:{:?}\n{}VM regs: {:08x?}\n",
                            get_indent(indent-1),
                            *vaddr,
                            vaddr >> 3,
                            insns[i],
                            frame_details.dw_die_offset,
                            frame_details.demangled_function_name,
                            frame_details.file_name,
                            frame_details.line_num,
                            frame_details.column,
                            get_indent(indent),
                            regs[i],
                        );

                let outer_fn_name = frame_details.demangled_function_name;

                let ins = insns[i].to_be_bytes();
                // eprintln!("{:02x?}", ins);

                let ins_type = ins[0];
                let _ins_dst = (ins[1] & 0xf) as usize;
                let _ins_src = ((ins[1] & 0xf0) >> 4) as usize;
                let ins_offset = ins[2] as u64 | ((ins[3] as u64) << 8);
                let _ins_immediate = u32::from_be_bytes(ins[4..].try_into().unwrap());
                if ins_type & ebpf::BPF_JMP == ebpf::BPF_JMP {
                    let next_pc = vaddr + 8;
                    let goto_pc = vaddr + 8 + ins_offset * 8;
                    let next_taken = vaddrs.iter().find(|e| **e == next_pc).is_some();
                    let goto_taken = vaddrs.iter().find(|e| **e == goto_pc).is_some();

                    if next_taken == false || goto_taken == false {
                        eprintln!(
                            "{}pcs_file: {}",
                            get_indent(indent),
                            pcs_path.to_string_lossy().to_string()
                        );
                        if let Ok(Some(frame)) = frames.peek() {
                            let frame_details = get_frame_details(&frame);

                            match (frame_details.file_name, frame_details.line_num) {
                                (Some(file), Some(line)) => {
                                    if next_taken == false {
                                        let goto_is_taken =
                                            get_frame_details_by_vaddr(&dwarf, goto_pc);
                                        eprintln!(
                                            "{}goto_is_taken frame: {:x?}",
                                            get_indent(indent),
                                            goto_is_taken
                                        );

                                        eprintln!(
                                            "{}outer fn: {:?}, inner fn: {:?}",
                                            get_indent(indent),
                                            outer_fn_name,
                                            frame_details.demangled_function_name
                                        );
                                        eprintln!(
                                            "{}next @0x{:x} not taken! Caller: {:?}@{}:{}",
                                            get_indent(indent),
                                            next_pc,
                                            frame_details.demangled_function_name,
                                            file,
                                            line
                                        );
                                        let mut branch_not_taken = Branch::NextNotTaken;
                                        if let Some(goto_is_taken) = goto_is_taken {
                                            // detect a compiler flip
                                            if goto_is_taken.demangled_function_name
                                                == frame_details.demangled_function_name
                                            {
                                                eprintln!(
                                                    "{}eBPF Compiler flip detected",
                                                    get_indent(indent)
                                                );
                                                branch_not_taken = Branch::GotoNotTaken;
                                            }
                                        }

                                        write_branch_lcov(file, line, branch_not_taken);
                                    } else if goto_taken == false {
                                        let next_is_taken =
                                            get_frame_details_by_vaddr(&dwarf, next_pc);
                                        eprintln!(
                                            "{}next_is_taken frame: {:x?}",
                                            get_indent(indent),
                                            next_is_taken
                                        );

                                        eprintln!(
                                            "{}goto branch @0x{:x} not taken!, Caller: {:?}@{}:{}",
                                            get_indent(indent),
                                            goto_pc,
                                            frame_details.demangled_function_name,
                                            file,
                                            line
                                        );
                                        let mut branch_not_taken = Branch::GotoNotTaken;
                                        if let Some(next_is_taken) = next_is_taken {
                                            // detect a compiler flip
                                            if next_is_taken.demangled_function_name
                                                == frame_details.demangled_function_name
                                            {
                                                branch_not_taken = Branch::GotoNotTaken;
                                                eprintln!(
                                                    "{}eBPF Compiler flip detected",
                                                    get_indent(indent)
                                                );
                                            }
                                        }
                                        write_branch_lcov(file, line, branch_not_taken);
                                    }
                                }
                                _ => {}
                            }
                        } else {
                            if next_taken == false {
                                eprintln!(
                                    "{}next branch @0x{:x} not taken! Not nested",
                                    get_indent(indent),
                                    next_pc
                                );
                            } else if goto_taken == false {
                                eprintln!(
                                    "{}goto branch @0x{:x} not taken! Not nested!",
                                    get_indent(indent),
                                    goto_pc
                                );
                            }
                        }
                    }
                }
                break; // only interested in the first frame deep, inners are just stack frames and we don't have the regs snapshots
            }
        }
    }

    // smoelius: A `vaddr` could not have an entry because its file does not exist. Keep only those
    // `vaddr`s that have entries.
    let vaddrs = vaddrs
        .into_iter()
        .filter(|vaddr| dwarf.vaddr_entry_map.contains_key(vaddr))
        .collect::<Vec<_>>();

    eprintln!("Line hits: {}", vaddrs.len());

    let file_line_count_map = build_file_line_count_map(&dwarf.vaddr_entry_map, vaddrs);

    write_lcov_file(pcs_path, file_line_count_map).map(Outcome::Lcov)
}

static CARGO_HOME: std::sync::LazyLock<PathBuf> = std::sync::LazyLock::new(|| {
    if let Some(cargo_home) = var_os("CARGO_HOME") {
        PathBuf::from(cargo_home)
    } else {
        #[allow(deprecated)]
        #[cfg_attr(
            dylint_lib = "inconsistent_qualification",
            allow(inconsistent_qualification)
        )]
        std::env::home_dir().unwrap().join(".cargo")
    }
});

fn build_vaddr_entry_map<'a>(loader: &'a Loader, debug_path: &Path) -> Result<VaddrEntryMap<'a>> {
    let mut vaddr_entry_map = VaddrEntryMap::new();
    let metadata = metadata(debug_path)?;
    for vaddr in (0..metadata.len()).step_by(size_of::<u64>()) {
        let location = loader.find_location(vaddr).map_err(|error| {
            anyhow!(
                "failed to find location for address 0x{vaddr:x}: {}",
                error.to_string()
            )
        })?;
        let Some(location) = location else {
            continue;
        };
        let Some(file) = location.file else {
            continue;
        };
        // smoelius: Ignore files that do not exist.
        if !Path::new(file).try_exists()? {
            continue;
        }
        if !include_cargo() && file.starts_with(CARGO_HOME.to_string_lossy().as_ref()) {
            continue;
        }
        let Some(line) = location.line else {
            continue;
        };
        // smoelius: Even though we ignore columns, fetch them should we ever want to act on them.
        let Some(_column) = location.column else {
            continue;
        };
        let entry = vaddr_entry_map.entry(vaddr).or_default();
        entry.file = file;
        entry.line = line;
    }
    Ok(vaddr_entry_map)
}

fn dump_vaddr_entry_map(vaddr_entry_map: BTreeMap<u64, Entry<'_>>) {
    let mut prev = String::new();
    for (vaddr, Entry { file, line }) in vaddr_entry_map {
        let curr = format!("{file}:{line}");
        if prev != curr {
            eprintln!("0x{vaddr:x}: {curr}");
            prev = curr;
        }
    }
}

fn read_vaddrs(pcs_path: &Path) -> Result<(Vaddrs, Insns, Regs)> {
    let mut regs = Regs::new();
    let mut insns = Insns::new();
    let mut vaddrs = Vaddrs::new();
    let mut pcs_file = File::open(pcs_path)?;

    let mut data_trace = [0u64; 13];
    'outer: loop {
        for i in 0..data_trace.len() {
            match pcs_file.read_u64::<LittleEndian>() {
                Err(_) => break 'outer,
                Ok(reg) => data_trace[i] = reg,
            }
        }

        // NB: the pc is instruction indexed, not byte indexed, keeps it aligned to 8 bytes - hence << 3 -> *8
        let vaddr = (data_trace[11] << 3) + 0x120; // TODO: Mind the .text offset in the dwarf - fix the hardcoded value.

        let mut data_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/pcs.txt")
            .expect("cannot open file");
        data_file.write_all(format!("0x{:08x?} all: {:08x?}\n", vaddr, data_trace).as_bytes())?;

        vaddrs.push(vaddr);
        insns.push(data_trace[12].to_be()); // we've stored the insn in data_trace[12] i.e the 13th element - 0..11 are the vm regs
        let regs_values: [u64; 12] = data_trace[0..12].try_into().unwrap();
        regs.push(regs_values);
    }

    Ok((vaddrs, insns, regs))
}

// fn read_vaddrs(pcs_path: &Path) -> Result<Vaddrs> {
//     let mut vaddrs = Vaddrs::new();
//     let mut pcs_file = File::open(pcs_path)?;
//     while let Ok(pc) = pcs_file.read_u64::<LittleEndian>() {
//         let vaddr = pc << 3;
//         let mut data_file = OpenOptions::new()
//             .create(true)
//             .append(true)
//             .open("/tmp/pcs.txt")
//             .expect("cannot open file");
//         data_file.write_all(format!("0x{:08x?}\n", vaddr).as_bytes())?;
//         vaddrs.push(vaddr);
//     }
//     Ok(vaddrs)
// }

fn find_applicable_dwarf<'a>(
    dwarfs: &'a [Dwarf],
    pcs_path: &Path,
    vaddrs: &mut [u64],
) -> Result<(&'a Dwarf, Option<Mismatch>)> {
    let dwarf_mismatches = collect_dwarf_mismatches(dwarfs, pcs_path, vaddrs)?;

    if let Some((dwarf, _)) = dwarf_mismatches
        .iter()
        .find(|(_, mismatch)| mismatch.is_none())
    {
        let vaddr_first = *vaddrs.first().unwrap();

        assert!(dwarf.start_address >= vaddr_first);

        let shift = dwarf.start_address - vaddr_first;

        // smoelius: Make the shift "permanent".
        for vaddr in vaddrs.iter_mut() {
            // *vaddr += shift;
        }

        return Ok((dwarf, None));
    }

    Ok(dwarf_mismatches
        .into_iter()
        .max_by_key(|(_, mismatch)| mismatch.as_ref().unwrap().index)
        .unwrap())
}

fn collect_dwarf_mismatches<'a>(
    dwarfs: &'a [Dwarf],
    pcs_path: &Path,
    vaddrs: &[u64],
) -> Result<Vec<(&'a Dwarf, Option<Mismatch>)>> {
    dwarfs
        .iter()
        .map(|dwarf| {
            let mismatch = dwarf_mismatch(vaddrs, dwarf, pcs_path)?;
            Ok((dwarf, mismatch))
        })
        .collect()
}

fn dwarf_mismatch(vaddrs: &[u64], dwarf: &Dwarf, pcs_path: &Path) -> Result<Option<Mismatch>> {
    use std::io::{Seek, SeekFrom};

    let Some(&vaddr_first) = vaddrs.first() else {
        return Ok(Some(Mismatch::default()));
    };

    if dwarf.start_address < vaddr_first {
        return Ok(Some(Mismatch::default()));
    }

    // smoelius: `start_address` is both an offset into the ELF file and a virtual address. The
    // current virtual addresses are offsets from the start of the text section. The current virtual
    // addresses must be shifted so that the first matches the start address.
    let shift = dwarf.start_address - vaddr_first;

    let mut so_file = File::open(dwarf.path.with_extension("so"))?;
    let mut insns_file = File::open(pcs_path.with_extension("insns"))?;

    for (index, &vaddr) in vaddrs.iter().enumerate() {
        let vaddr = vaddr + shift;

        so_file.seek(SeekFrom::Start(vaddr))?;
        let expected = so_file.read_u64::<LittleEndian>()?;

        let actual = insns_file.read_u64::<LittleEndian>()?;

        // smoelius: 0x85 is a function call. That they would be patched and differ is not
        // surprising.
        if expected & 0xff == 0x85 {
            continue;
        }

        if expected != actual {
            return Ok(Some(Mismatch {
                index,
                vaddr: Vaddr::from(vaddr),
                expected: Insn::from(expected),
                actual: Insn::from(actual),
            }));
        }
    }

    Ok(None)
}

fn write_closest_match(pcs_path: &Path, dwarf: &Dwarf, mismatch: Mismatch) -> Result<PathBuf> {
    let closest_match_path = pcs_path.with_extension("closest_match");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&closest_match_path)?;
    writeln!(
        file,
        "{:#?}",
        ClosestMatch {
            pcs_path,
            debug_path: &dwarf.path,
            mismatch
        }
    )?;
    Ok(closest_match_path)
}

fn build_file_line_count_map<'a>(
    vaddr_entry_map: &BTreeMap<u64, Entry<'a>>,
    vaddrs: Vaddrs,
) -> FileLineCountMap<'a> {
    let mut file_line_count_map = FileLineCountMap::new();
    for Entry { file, line } in vaddr_entry_map.values() {
        let line_count_map = file_line_count_map.entry(file).or_default();
        line_count_map.insert(*line, 0);
    }

    for vaddr in vaddrs {
        // smoelius: A `vaddr` could not have an entry because its file does not exist.
        let Some(entry) = vaddr_entry_map.get(&vaddr) else {
            continue;
        };
        let line_count_map = file_line_count_map.get_mut(entry.file).unwrap();
        let count = line_count_map.get_mut(&entry.line).unwrap();
        *count += 1;
    }

    file_line_count_map
}

fn write_lcov_file(pcs_path: &Path, file_line_count_map: FileLineCountMap<'_>) -> Result<PathBuf> {
    let lcov_path = Path::new(pcs_path).with_extension("lcov");

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&lcov_path)?;

    for (source_file, line_count_map) in file_line_count_map {
        // smoelius: Stripping `current_dir` from `source_file` has not effect on what's displayed.
        writeln!(file, "SF:{source_file}")?;
        for (line, count) in line_count_map {
            writeln!(file, "DA:{line},{count}")?;
        }
        writeln!(file, "end_of_record")?;
    }

    Ok(lcov_path)
}

fn include_cargo() -> bool {
    var_os("INCLUDE_CARGO").is_some()
}
