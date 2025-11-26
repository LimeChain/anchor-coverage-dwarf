use addr2line::Loader;
use anyhow::{Result, anyhow};
use byteorder::{LittleEndian, ReadBytesExt};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{File, OpenOptions, metadata},
    io::Write,
    path::{Path, PathBuf},
};

mod branch;

mod start_address;
use start_address::start_address;

pub mod util;
use util::StripCurrentDir;

use crate::util::{compute_hash, find_files_with_extension};

mod vaddr;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Entry<'a> {
    file: &'a str,
    line: u32,
}

struct Dwarf {
    path: PathBuf,
    #[allow(dead_code)]
    so_path: PathBuf,
    so_hash: String,
    start_address: u64,
    #[allow(dead_code, reason = "`vaddr` points into `loader`")]
    loader: &'static Loader,
    vaddr_entry_map: BTreeMap<u64, Entry<'static>>,
}

enum Outcome {
    Lcov(PathBuf),
}

type Vaddrs = Vec<u64>;
type Insns = Vec<u64>;
type Regs = Vec<[u64; 12]>;

type VaddrEntryMap<'a> = BTreeMap<u64, Entry<'a>>;

type FileLineCountMap<'a> = BTreeMap<&'a str, BTreeMap<u32, usize>>;

pub fn run(sbf_trace_dir: PathBuf, debug: bool) -> Result<()> {
    let mut lcov_paths = Vec::new();

    let debug_paths = debug_paths()?;
    let src_paths = src_paths()?;
    eprintln!("src_paths: {:?}", src_paths);

    let dwarfs = debug_paths
        .into_iter()
        .map(|path| build_dwarf(&path, &src_paths))
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

    let regs_paths = find_files_with_extension(std::slice::from_ref(&sbf_trace_dir), "regs");

    for regs_path in &regs_paths {
        match process_regs_path(&dwarfs, regs_path, &src_paths) {
            Ok(Outcome::Lcov(lcov_path)) => {
                lcov_paths.push(lcov_path.strip_current_dir().to_path_buf());
            }
            _ => {
                eprintln!("Skipping Regs file: {}", regs_path.to_string_lossy());
            }
        }
    }

    eprintln!(
        "
Processed {} of {} regs files

Lcov files written: {lcov_paths:#?}

If you are done generating lcov files, try running:

    genhtml --output-directory coverage {}/*.lcov --rc branch_coverage=1 && open coverage/index.html
",
        lcov_paths.len(),
        regs_paths.len(),
        sbf_trace_dir.as_path().strip_current_dir().display()
    );

    Ok(())
}

fn src_paths() -> Result<HashSet<PathBuf>> {
    let mut src_paths = HashSet::new();
    for src_path in std::env::var("SRC_PATHS")?.split(",") {
        src_paths.insert(PathBuf::from(src_path));
    }
    Ok(src_paths)
}

fn debug_paths() -> Result<Vec<PathBuf>> {
    let sbf_paths = std::env::var("SBF_PATHS")?
        .split(',')
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    let debug_files = find_files_with_extension(&sbf_paths, "debug");
    Ok(debug_files)
}

fn build_dwarf(debug_path: &Path, src_paths: &HashSet<PathBuf>) -> Result<Dwarf> {
    let start_address = start_address(debug_path)?;

    let loader = Loader::new(debug_path).map_err(|error| {
        anyhow!(
            "failed to build loader for {}: {}",
            debug_path.display(),
            error.to_string()
        )
    })?;

    let loader = Box::leak(Box::new(loader));

    let vaddr_entry_map = build_vaddr_entry_map(loader, debug_path, src_paths)?;

    let so_path = debug_path.with_extension("so");
    let so_hash = compute_hash(&std::fs::read(&so_path)?);

    Ok(Dwarf {
        path: debug_path.to_path_buf(),
        so_path,
        so_hash,
        start_address,
        loader,
        vaddr_entry_map,
    })
}

fn process_regs_path(
    dwarfs: &[Dwarf],
    regs_path: &Path,
    src_paths: &HashSet<PathBuf>,
) -> Result<Outcome> {
    eprintln!();
    eprintln!("Regs file: {}", regs_path.strip_current_dir().display());

    let (mut vaddrs, regs) = read_vaddrs(regs_path)?;
    eprintln!("Regs read: {}", vaddrs.len());
    let insns = read_insns(&regs_path.with_extension("insns"))?;

    let dwarf = find_applicable_dwarf(dwarfs, regs_path, &mut vaddrs)?;

    eprintln!(
        "Applicable dwarf: {}",
        dwarf.path.strip_current_dir().display()
    );

    assert!(
        vaddrs
            .first()
            .is_some_and(|&vaddr| vaddr == dwarf.start_address)
    );

    // smoelius: If a sequence of Regs refer to the same file and line, treat them as
    // one hit to that file and line.
    // vaddrs.dedup_by_key::<_, Option<&Entry>>(|vaddr| dwarf.vaddr_entry_map.get(vaddr));

    if let Ok(branches) = branch::get_branches(&vaddrs, &insns, &regs, dwarf) {
        let _ = branch::write_branch_coverage(&branches, regs_path, src_paths);
    }

    // smoelius: A `vaddr` could not have an entry because its file does not exist. Keep only those
    // `vaddr`s that have entries.
    let vaddrs = vaddrs
        .into_iter()
        .filter(|vaddr| dwarf.vaddr_entry_map.contains_key(vaddr))
        .collect::<Vec<_>>();

    eprintln!("Line hits: {}", vaddrs.len());

    let file_line_count_map = build_file_line_count_map(&dwarf.vaddr_entry_map, vaddrs);

    write_lcov_file(regs_path, file_line_count_map).map(Outcome::Lcov)
}

fn build_vaddr_entry_map<'a>(
    loader: &'a Loader,
    debug_path: &Path,
    src_paths: &HashSet<PathBuf>,
) -> Result<VaddrEntryMap<'a>> {
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
        // procdump: ignore files other than what user has provided.
        if !src_paths
            .iter()
            .any(|src_path| file.starts_with(&src_path.to_string_lossy().to_string()))
        {
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

fn read_insns(insns_path: &Path) -> Result<Insns> {
    let mut insns = Vec::new();
    let mut insns_file = File::open(insns_path)?;
    while let Ok(insn) = insns_file.read_u64::<LittleEndian>() {
        insns.push(insn);
    }
    Ok(insns)
}

fn read_vaddrs(regs_path: &Path) -> Result<(Vaddrs, Regs)> {
    let mut regs = Regs::new();
    let mut vaddrs = Vaddrs::new();
    let mut regs_file = File::open(regs_path)?;

    let mut data_trace = [0u64; 12];
    'outer: loop {
        for item in &mut data_trace {
            match regs_file.read_u64::<LittleEndian>() {
                Err(_) => break 'outer,
                Ok(reg) => *item = reg,
            }
        }

        // NB: the pc is instruction indexed, not byte indexed, keeps it aligned to 8 bytes - hence << 3 -> *8
        let vaddr = data_trace[11] << 3;

        vaddrs.push(vaddr);
        let regs_values: [u64; 12] = data_trace[0..12].try_into().unwrap();
        regs.push(regs_values);
    }

    Ok((vaddrs, regs))
}

fn find_applicable_dwarf<'a>(
    dwarfs: &'a [Dwarf],
    regs_path: &Path,
    vaddrs: &mut [u64],
) -> Result<&'a Dwarf> {
    // Get the SHA-256 identifier for the Executable that has generated this tracing data.
    let exec_sha256 = std::fs::read_to_string(regs_path.with_extension("exec.sha256"))?;
    let dwarf = dwarfs
        .iter()
        .find(|dwarf| dwarf.so_hash == exec_sha256)
        .ok_or(anyhow!(
            "Cannot find the shared object that corresponds to: {}",
            exec_sha256
        ))?;

    let vaddr_first = *vaddrs.first().unwrap();
    assert!(dwarf.start_address >= vaddr_first);
    let shift = dwarf.start_address - vaddr_first;

    // smoelius: Make the shift "permanent".
    for vaddr in vaddrs.iter_mut() {
        *vaddr += shift;
    }

    Ok(dwarf)
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

fn write_lcov_file(regs_path: &Path, file_line_count_map: FileLineCountMap<'_>) -> Result<PathBuf> {
    let lcov_path = Path::new(regs_path).with_extension("lcov");

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
