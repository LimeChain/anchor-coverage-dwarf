# sbpf-coverage

A tool for computing test code coverage of Solana programs.

## Prerequisites

Install `lcov` to generate HTML coverage reports:

```sh
# macOS
brew install lcov

# Ubuntu/Debian
sudo apt install lcov

# Fedora
sudo dnf install lcov
```

## Steps to use

1. Add the following to `[profile.release]` section of your Solana program's Cargo.toml:

   ```toml
   debug = true
   lto = "off"
   opt-level = 0
   ```

   This tells Cargo to build with debug information, without optimizations.
   Be sure to also use SBF Version 1 allowing for dynamic stack frames. This is necessary
   in the case of working without optimizations. Also be sure to use the latest platform-tools version v1.51 or higher.

   ```sh
   cargo build-sbf --debug --tools-version v1.51 --arch v1
   ```

2. Execution:

   This tool is agnostic from the framework used (Anchor, StarFrame, Typhoon)
   for collecting the tracing data. In other words it's up to the user to
   generate the register tracing data which can later be ingested with this tool.

   For example in the case of having a few Rust tests for your program using either
   LiteSVM (or maybe some TS tests) or Mollusk you would typically do:

   ```sh
   SBF_TRACE_DIR=$PWD/sbf_trace_dir cargo test -- --nocapture
   ```

   After the tests are finished the register tracing data will be dumped into `sbf_trace_dir`
   and this is the data this tool can ingest and generate code coverage statistics on top of.

   Finally after having executed your tests:

   ```sh
   RUST_BACKTRACE=1 sbpf-coverage \
      --src-path=$PWD/programs/myapp/src/ \
      --sbf-path=$PWD/target/deploy \
      --sbf-trace-dir=$PWD/sbf_trace_dir
   ```
  
   This would work for a program called myapp.

3. Run the following command to generate and open an HTML coverage report:

   ```sh
   genhtml --output-directory coverage sbf_trace_dir/*.lcov --rc branch_coverage=1 && open coverage/index.html
   ```

## Known problems

`sbpf-coverage` uses Dwarf debug information, not LLVM instrumentation-based coverage, to map instructions to source code locations. This can have confusing implications. For example:

- one line can appear directly before another
- the latter line can have a greater number of hits

The reason is that multiple instructions can map to the same source line. If multiple instructions map to the latter source line, it can have a greater number of hits than the former.

The following is an example. The line with the assignment to `signer` is hit only once. But the immediately following line is hit multiple times, because the instructions that map to it are interspersed with instructions that map elsewhere.

```rs
            5 :     pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
            1 :         let signer = &ctx.accounts.signer;
            4 :         let pubkey = signer.signer_key().unwrap();
           11 :         msg!("Signer's pubkey is: {}", pubkey);
            1 :         Ok(())
            1 :     }
```

## Troubleshooting

- If you see:
  ```
  Line hits: 0
  ```
  Check that you added `debug = true` to the `[profile.release]` section of your Anchor project's root Cargo.toml.
