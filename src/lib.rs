use addr2line::Loader;
use anyhow::{Result, anyhow, bail};
use byteorder::{LittleEndian, ReadBytesExt};
use object::{Object, ObjectSection};
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

pub fn run(
    sbf_trace_dir: PathBuf,
    src_paths: HashSet<PathBuf>,
    sbf_paths: Vec<PathBuf>,
    debug: bool,
) -> Result<()> {
    let mut lcov_paths = Vec::new();

    let debug_paths = debug_paths(sbf_paths)?;

    let dwarfs = debug_paths
        .into_iter()
        .map(|path| build_dwarf(&path, &src_paths))
        .collect::<Result<Vec<_>>>()
        .expect("Can't build dwarf");

    if dwarfs.is_empty() {
        bail!("Found no .so/.debug/.so.debug files containing debug sections.");
    }

    if debug {
        for dwarf in dwarfs {
            dump_vaddr_entry_map(dwarf.vaddr_entry_map);
        }
        eprintln!("Exiting debug mode.");
        return Ok(());
    }

    let regs_paths = find_files_with_extension(std::slice::from_ref(&sbf_trace_dir), "regs");
    if regs_paths.is_empty() {
        bail!(
            "Found no regs files in: {}
Are you sure you run your tests with register tracing enabled",
            sbf_trace_dir.strip_current_dir().display(),
        );
    }

    for regs_path in &regs_paths {
        match process_regs_path(&dwarfs, regs_path, &src_paths) {
            Ok(Outcome::Lcov(lcov_path)) => {
                lcov_paths.push(lcov_path.strip_current_dir().to_path_buf());
            }
            _ => {
                eprintln!(
                    "Skipping Regs file: {} (no matching executable)",
                    regs_path.strip_current_dir().display()
                );
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

fn debug_paths(sbf_paths: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    // It's possible that the debug information is in the .so file itself
    let so_files = find_files_with_extension(&sbf_paths, "so");
    // It's also possible that it ends with .debug
    let debug_files = find_files_with_extension(&sbf_paths, "debug");

    let mut maybe_list = so_files;
    maybe_list.extend(debug_files);

    // Collect only those files that contain debug sections
    let full_list = maybe_list
        .into_iter()
        .filter(|maybe_path| {
            let Ok(data) = std::fs::read(maybe_path) else {
                return false;
            };
            let Ok(object) = object::read::File::parse(&*data) else {
                return false;
            };
            // check it has debug sections
            object
                .sections()
                .any(|section| section.name().is_ok_and(|n| n.starts_with(".debug_")))
        })
        .collect();

    eprintln!("Files containing debug sections: {:#?}", full_list);
    Ok(full_list)
}

fn build_dwarf(debug_path: &Path, src_paths: &HashSet<PathBuf>) -> Result<Dwarf> {
    let start_address = start_address(debug_path)?;

    let loader = Loader::new(debug_path).map_err(|error| {
        anyhow!(
            "failed to build loader for {}: {}",
            debug_path.display(),
            error
        )
    })?;

    let loader = Box::leak(Box::new(loader));

    eprintln!(
        "Trying to build a DWARF entry with debug path: {}",
        debug_path.strip_current_dir().display()
    );

    let vaddr_entry_map = build_vaddr_entry_map(loader, debug_path, src_paths)?;

    // Suppose debug_path is program.debug, swap with .so and try
    let mut so_path = debug_path.with_extension("so");
    let so_content = match std::fs::read(&so_path) {
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                // We might have program.so.debug - simply cut debug and try
                so_path = debug_path.with_extension("");
                std::fs::read(&so_path)?
            } else {
                return Err(e.into());
            }
        }
        Ok(c) => c,
    };
    let so_hash = compute_hash(&so_content);
    eprintln!(
        "Found a match:\n{} to\n{} (SHA-256: {})",
        debug_path.strip_current_dir().display(),
        so_path.strip_current_dir().display(),
        &so_hash[..16],
    );

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
    let exec_sha256 = std::fs::read_to_string(regs_path.with_extension("exec.sha256"))?;
    eprintln!(
        "Regs file: {} (expecting executable with SHA-256: {})",
        regs_path.strip_current_dir().display(),
        &exec_sha256[..16]
    );

    let (mut vaddrs, regs) = read_vaddrs(regs_path)?;
    eprintln!("Regs read: {}", vaddrs.len());
    let insns = read_insns(&regs_path.with_extension("insns"))?;

    let dwarf = find_applicable_dwarf(dwarfs, regs_path, &exec_sha256, &mut vaddrs)?;

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
            anyhow!("failed to find location for address 0x{vaddr:x}: {}", error)
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
        regs.push(data_trace);
    }

    Ok((vaddrs, regs))
}

fn find_applicable_dwarf<'a>(
    dwarfs: &'a [Dwarf],
    regs_path: &Path,
    exec_sha256: &str,
    vaddrs: &mut [u64],
) -> Result<&'a Dwarf> {
    let dwarf = dwarfs
        .iter()
        .find(|dwarf| dwarf.so_hash == exec_sha256)
        .ok_or(anyhow!(
            "Cannot find the shared object that corresponds to: {}",
            exec_sha256
        ))?;

    eprintln!(
        "Matching Regs file {} to executable with SHA-256: {}",
        regs_path.strip_current_dir().display(),
        &dwarf.so_hash[..16]
    );
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
    let lcov_path = regs_path.with_extension("lcov");

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
