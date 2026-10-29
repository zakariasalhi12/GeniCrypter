
// $> polymorph --help
// Polymorphic Program Usage:
//   --generate <output-binary>       Generate a polymorphic binary.
//   --payload <reverse-shell-code>   Embed the reverse shell payload.
// $> polymorph --generate polymorphic.exe --payload reverse_shell_payload
// Polymorphic binary generated successfully as "polymorphic.exe".
// $> polymorphic.exe
// [INFO] Polymorphic signature updated successfully.
// [INFO] Reverse shell initialized. Attempting connection to attacker...


fn main() {
    println!("Hello, world!");
}
