pub struct Stub  {
    encrepted_exe : String,
    delay : u32,
    added_size: u32,
    key : String
}


impl Stub {
    pub fn new(encrepted_exe : String , delay : u32 ,added_size : u32 , key: String) -> Stub {
        Stub {
            encrepted_exe,
            delay,
            added_size,
            key
        }
    }
    pub fn decrypt() {

    }
}