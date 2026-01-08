use byteorder::{BigEndian, ByteOrder};
use std::fs::File;
use std::io::Read;

pub struct DNSHeader {
    id: u16,              // ID - 16 bits
    query_response: bool, // QR - 1 bit | 0=false for Queries, 1=true for Responses
    // op_code: u8,                // OPCODE - 4 bits
    authoritative_answer: bool, // AA - 1 bit
    truncated_message: bool,    // TC - 1 bit
    recursion_desired: bool,    // RD - 1 bit
                                // recursion_available: bool,  // RA - 1 bit
                                // reserved: u8,               // Z - 3 bits
                                // response_code: u8,          // RCODE - 4 bits
                                // question_count: u16,        // QDCOUNT - 16 bits
                                // answer_count: u16,          // ANCOUNT - 16 bits
                                // authority_count: u16,       // NSCOUNT - 16 bits
                                // additional_count: u16,      // ARCOUNT - 16 bits
}
pub struct DNSPacket {
    header: DNSHeader,
}

impl DNSPacket {
    pub fn from_buffer(buffer: [u8; 512]) -> DNSPacket {
        let header_bytes = &buffer[0..13];
        let id_bytes = &header_bytes[0..2];
        let id = BigEndian::read_u16(id_bytes);

        let header = DNSHeader {
            id: id,
            query_response: header_bytes[2] & (1u8 << 7u8) != 0,
            authoritative_answer: header_bytes[2] & (1u8 << 2u8) != 0,
            truncated_message: header_bytes[2] & (1u8 << 1u8) != 0,
            recursion_desired: header_bytes[2] & (1u8) != 0,
        };

        DNSPacket { header }
    }
}

fn main() -> std::io::Result<()> {
    let mut file = File::open("query_packet.txt")?;
    let mut buffer: [u8; 512] = [0; 512];
    file.read(&mut buffer)?;

    let packet: DNSPacket = DNSPacket::from_buffer(buffer);
    println!("ID: {}", packet.header.id);
    println!("QR: {}", packet.header.query_response);
    println!("AA: {}", packet.header.authoritative_answer);
    println!("TC: {}", packet.header.truncated_message);
    println!("RD: {}", packet.header.recursion_desired);

    Ok(())
}
