use std::net::UdpSocket;

fn main() {
    let socket = UdpSocket::bind("127.0.0.1:5555").expect("Can't open socket!");
    socket
        .send_to(&[5; 10], "127.0.0.1:6666")
        .expect("Couldn't send data");
}
