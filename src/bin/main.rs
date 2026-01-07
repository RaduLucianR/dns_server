use std::fs::File;
use std::io::Read;

fn main() -> std::io::Result<()> {
    let mut file = File::open("response_packet.txt")?;
    let mut words: [u8; 512] = [0; 512];
    file.read(&mut words)?;

    for word in words {
        println!("{}", word);
    }

    Ok(())
}
