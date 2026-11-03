pub struct Stub  {
    encrypted_bin : String,
    output : String,
    delay : u64,
    padding: u32,
    key : String,
    verbose : Boolean,
    vm_detection : Boolean
}

impl Stub {
    pub fn new(
        encrypted_bin : String,
        output : String,
        delay : u64,
        padding : u32,
        key: String,
        verbose: Boolean,
        vm_detection: Boolean
    ) -> Stub {
        Stub {
            encrypted_bin,
            output,
            delay,
            padding,
            key,
            verbose,
            vm_detection
        }
    }

    pub fn vm_detection(stub: &Stub) {
        let is_vm = false;

        if is_vm {
            if stub.verbose {
                println!("[INFO] VM detected. Exiting...");
            }
            std::process::exit(0);
        }
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

    pub fn anti_debug() -> bool {
        match anti_debug::is_debugger_present() {
            Ok(true) => true,
            Ok(false) => false,
            Err(_) => false,
        }
    }
}

fn main() {
    // Check if the program is running in a VM
    if vm_detection {
        Stub::vm_detection(&stub);
    }

    // Check if the program is being debugged
    if Stub::anti_debug() {
        if stub.verbose {
            println!("[INFO] Debugger detected. Exiting...");
        }
        std::process::exit(0);
    }


    Stub::delay_execution(&stub);
    Stub::decrypt(&stub);
    Stub::execute(&stub);
}

