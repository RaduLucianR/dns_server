use std::fs::File;
use std::io::Read;

pub struct DNSPacket {
    pub buffer: [u8; 512],
}

impl DNSPacket {
    pub fn new() -> DNSPacket {
        DNSPacket { buffer: [0; 512] }
    }
}

fn main() -> std::io::Result<()> {
    let mut file = File::open("query_packet.txt")?;
    let mut packet = DNSPacket::new();
    file.read(&mut packet.buffer)?;

    for i in 0..8 {
        println!("{}", packet.buffer[i]);
    }

    Ok(())
}
