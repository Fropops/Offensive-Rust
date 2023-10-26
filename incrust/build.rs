fn main() {
    //force rebuild everytime => allow to take in account env. variable changes
    println!("cargo:rerun-if-changed=src/payload.b64"); 
} 