# hidden-bytes



```bash
cargo +nightly rustc --target x86_64-pc-windows-gnu --release -- \
  -Zllvm-plugins="/path/to/LLVMObfuscationx.dll" \
  -Cpasses="irobf(irobf-indbr,irobf-icall,irobf-indgv,irobf-cff)"
```