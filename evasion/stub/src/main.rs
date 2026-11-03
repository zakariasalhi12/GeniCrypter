pub struct Stub  {
    encrypted_bin : String,
    output : String,
    delay : u64,
    padding: u32,
    key : String,
    verbose : Boolean,
}

impl Stub {
    pub fn new(encrypted_bin : String , output : String, delay : u64 ,padding : u32 , key: String, verbose: Boolean) -> Stub {
        Stub {
            encrypted_bin,
            output,
            delay,
            padding,
            key,
            verbose
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
}

fn main() {

    Stub::delay_execution(&stub);
    Stub::decrypt(&stub);
    Stub::execute(&stub);
}