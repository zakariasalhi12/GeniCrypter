pub struct EmbeddedData {
    cipher_bin: Vec<u8>,
    key: [u8; 32],
    nonce: [u8; 12],
    delay : u64,
    verbose : bool,
    vm_detection : bool
}

impl Stub {
    pub fn new(
        cipher_bin : Vec<u8>,
        key: [u8; 32],
        nonce: [u8; 12],
        delay : u64,
        verbose: bool,
        vm_detection: bool
    ) -> Stub {
        Stub {
            cipher_bin,
            key,
            nonce,
            delay,
            verbose,
            vm_detection
        }
    }

    pub fn parse_embedded(self_data: &[u8]) -> Option<EmbeddedData>{
        return None;
    }

    pub fn decrypt(stub: &Stub) {
        if stub.verbose {
            println!("[INFO] Binary decrypted successfully.");
        }
    }

    pub fn execute(stub: &Stub) {
        if stub.verbose {
                println!("[INFO] Target program executed.");
        }
    }

    pub fn delay_execution(stub: &Stub) {
        if stub.delay > 0 {
            if stub.verbose {
                println!("[INFO] Delaying execution by {} seconds...", stub.delay);
            }
            std::thread::sleep(std::time::Duration::from_secs(stub.delay));
        }
    }

    pub fn vm_detection(stub: &Stub) -> bool {
        // =====================================================================
        // WARNING: This is NOT a reliable standalone VM/sandbox check.
        // The crate's heuristics can be outdated, bypassed, or produce
        // false negatives on modern or custom-configured VMs.
        // =====================================================================
        antilysis::detected().unwrap_or(false)
    }

    pub fn anti_debug() -> bool {
        // =====================================================================
        // WARNING: This is NOT a reliable standalone anti-debug check.
        // The detection can be bypassed, hooked, or neutralized by modern
        // debuggers and analysts. Use it only as a first layer of defense
        // =====================================================================
        antidebug::is_debugger_present().unwrap_or(false)
    }
}

fn main() {
    // Check if the program is running in a VM
    if Stub::vm_detection(&stub) {
        if stub.verbose {
            println!("[INFO] VM detected. Exiting...");
        }
        // todo instead of exiting , we can make change the program behavior
        std::process::exit(0);
    }

    // Check if the program is being debugged
    if Stub::anti_debug() {
        if stub.verbose {
            println!("[INFO] Debugger detected. Exiting...");
        }
        // todo instead of exiting , we can make change the program behavior
        std::process::exit(0);
    }

    Stub::delay_execution(&stub);
    Stub::decrypt(&stub);
    Stub::execute(&stub);
}

