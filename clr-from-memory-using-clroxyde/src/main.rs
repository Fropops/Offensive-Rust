use clroxide::clr::Clr;

use std::error::Error;
use std::fs;

fn main() {
    match inner_main() {
        Err(e) => println!("{}", e.to_string()),
        _ => {}
    }
}

pub fn inner_main() -> Result<(),Box<dyn Error>> {
    //(!) if loading a signatured .net file, if amsi is not bypassed, it will throw an error
    let contents = fs::read("E:\\Share\\Projects\\Rust\\Offensive-rust\\clr-from-file\\.net\\Test\\bin\\Debug\\Test.exe")?;
    //dbg!(&contents);

    let cmd_args : Vec<String> = vec![];
    let mut clr = Clr::new(contents, cmd_args)?;

    let results = clr.run()?;

    println!("{}", results);
    Ok(())
}


