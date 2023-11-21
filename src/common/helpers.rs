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