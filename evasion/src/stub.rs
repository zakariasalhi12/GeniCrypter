pub struct Stub  {
    encrepted_exe : String,
    delay : u32,
    added_size: u32
}


impl Stub {
    pub fn new(encrepted_exe : String , delay : u32 ,added_size : u32 ) -> Stub {
        Stub {
            encrepted_exe,
            delay,
            added_size
        }
    }
    pub fn decrypt() {

    }
}