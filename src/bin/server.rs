use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
    println!("Starting server...");
    let socket = UdpSocket::bind("127.0.0.1:6666")?;
    let mut buffer = [0; 10];
    loop {
        let result = socket.recv_from(&mut buffer);

        match result {
            Ok(_) => {
                println!("Message received!")
            }
            Err(e) => eprint!("An error occurred: {}", e),
        }
    }
}
