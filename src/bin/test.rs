fn main() {
    let x: u8 = 0b00010000;
    println!("x is {} in decimal, {:b} in binary", x, x);

    let a: u8 = (1 << 1);
    println!("{:#b}", a);

    for i in 0u8..8 {
        println!("Bit {} is set? {}", i, x & (1 << i) != 0);
    }
}
