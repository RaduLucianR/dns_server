use byteorder::{BigEndian, ByteOrder};
use std::fmt::Display;
use std::fs::File;
use std::io::Read;

#[derive(Debug)]
pub struct DNSHeader {
    id: u16,                    // ID - 16 bits
    query_response: bool,       // QR - 1 bit | 0=false for Queries, 1=true for Responses
    op_code: u8,                // OPCODE - 4 bits
    authoritative_answer: bool, // AA - 1 bit
    truncated_message: bool,    // TC - 1 bit
    recursion_desired: bool,    // RD - 1 bit
    recursion_available: bool,  // RA - 1 bit
    // Z - 3 bits (RFC 1035), but now they are 3 flags: |Z|AD|CD| (see RFC 6895). TODO: Find out what they mean
    reserved: u8,
    response_code: u8,     // RCODE - 4 bits
    question_count: u16,   // QDCOUNT - 16 bits
    answer_count: u16,     // ANCOUNT - 16 bits
    authority_count: u16,  // NSCOUNT - 16 bits
    additional_count: u16, // ARCOUNT - 16 bits
}

impl Display for DNSHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let query_response = match self.query_response {
            false => "QUERY",
            true => "RESPONSE",
        };

        write!(
            f,
            "DNS Header
            ID:      {}
            QR:      {}
            OPCODE:  {}
            AA:      {}
            TC:      {}
            RD:      {}
            RA:      {}
            Z:       {}
            RCODE:   {}
            QDCOUNT: {}
            ANCOUNT: {}
            NSCOUNT: {}
            ARCOUNT: {}
            ",
            self.id,
            query_response,
            self.op_code,
            self.authoritative_answer,
            self.truncated_message,
            self.recursion_desired,
            self.recursion_available,
            self.reserved,
            self.response_code,
            self.question_count,
            self.answer_count,
            self.authority_count,
            self.additional_count
        )
    }
}

#[derive(Debug)]
pub struct DNSPacket {
    header: DNSHeader,
}

// impl Display for DNSPacket {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "")
//     }
// }

impl DNSPacket {
    pub fn from_buffer(buffer: [u8; 512]) -> DNSPacket {
        let header_bytes = &buffer[0..13];

        let header = DNSHeader {
            id: BigEndian::read_u16(&header_bytes[0..2]), // Bytes 0-1

            // Byte 2
            query_response: header_bytes[2] & (1u8 << 7u8) != 0,
            op_code: (header_bytes[2] & 0b0111_1000) >> 3u8, //==64+32+16+8=120
            authoritative_answer: header_bytes[2] & (1u8 << 2u8) != 0,
            truncated_message: header_bytes[2] & (1u8 << 1u8) != 0,
            recursion_desired: header_bytes[2] & (1u8) != 0,

            // Byte 3
            recursion_available: header_bytes[3] & (1u8 << 7u8) != 0,
            reserved: (header_bytes[3] & 0b0111_0000) >> 4u8,
            response_code: header_bytes[3] & 0b0000_1111,

            question_count: BigEndian::read_u16(&header_bytes[4..6]), // Bytes 4-5
            answer_count: BigEndian::read_u16(&header_bytes[6..8]),   // Bytes 6-7
            authority_count: BigEndian::read_u16(&header_bytes[8..10]), // Bytes 8-9
            additional_count: BigEndian::read_u16(&header_bytes[10..12]), // Bytes 10-11
        };

        DNSPacket { header }
    }
}

fn main() -> std::io::Result<()> {
    let mut file = File::open("query_packet.txt")?;
    let mut buffer: [u8; 512] = [0; 512];
    file.read(&mut buffer)?;

    let packet: DNSPacket = DNSPacket::from_buffer(buffer);
    println!("{:#?}", packet);

    Ok(())
}
