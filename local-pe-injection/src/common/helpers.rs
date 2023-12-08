use std::io::{self, Write, Read};

use base64::{Engine as _, engine::general_purpose};

#[allow(dead_code)]
pub fn base64_to_vec(str_b64:&str) -> Vec<u8> {
    general_purpose::STANDARD.decode(str_b64).unwrap()
}

#[allow(dead_code)]
pub fn vec_to_base64(bytes: Vec<u8>) -> String {
    general_purpose::STANDARD.encode(&bytes)
}

#[allow(dead_code)]
pub fn ascii_bytes_to_string(bytes: &[u8]) -> String {
    let mut name = String::new();
    for index in 0..bytes.len() {
        let c = bytes[index] as char;
        if c != (0 as char) {
            name.push(c);
        }
        else {
            break;
        }
    }
    name
}

#[allow(dead_code)]
pub fn pause() {
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    // We want the cursor to stay at the end of the line, so we print without a newline and flush manually.
    write!(stdout, "Press any key to continue...").unwrap();
    stdout.flush().unwrap();

    // Read a single byte and discard
    let _ = stdin.read(&mut [0u8]).unwrap();
}