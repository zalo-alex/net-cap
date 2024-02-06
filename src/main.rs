use pcap::{Capture, Device};
use std::iter::Peekable;
use std::io;
use std::io::Write;

// Custom bytes iterator
struct NextInts<'a> {
    bytes: Peekable<std::slice::Chunks<'a, u8>>,
}

impl<'a> NextInts<'a> {
    fn new(data: &'a [u8]) -> Self {
        let chunk_size = std::mem::size_of::<u8>();
        NextInts {
            bytes: data.chunks(chunk_size).peekable(),
        }
    }

    fn next_ints(&mut self, count: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(count);
        for _ in 0..count {
            if let Some(chunk) = self.bytes.next() {
                result.push(chunk[0]);
            } else {
                break;
            }
        }
        result
    }
}

// Show all devices with their name and description
fn show_devices() {
    let devices = Device::list().unwrap();

    for device in devices {
        println!("Device: {} : {}", device.name, device.desc.unwrap());
    };
}

// Find the divice with the name
fn get_requested_device<'a> (requested_device_s : String, requested_device : &'a mut Device, vec_devices : &'a Vec<Device>) {
    for device in vec_devices {
        if device.name == requested_device_s {
            requested_device.name = device.name.clone();
            requested_device.desc = device.desc.clone();
        };
    };
}


fn main() {
    show_devices();

    // Read user input for device name
    let mut device_name = String::new();

    print!("Device name: ");
    io::stdout().flush().unwrap();

    io::stdin().read_line(&mut device_name).expect("Did not enter a correct string");

    if let Some('\n')=device_name.chars().next_back() {
        device_name.pop();
    }
    if let Some('\r')=device_name.chars().next_back() {
        device_name.pop();
    }

    // Init device
    let devices = Device::list().unwrap();
    let mut device = Device::lookup().unwrap().unwrap();

    get_requested_device(device_name, &mut device, &devices);

    let mut cap = Capture::from_device(device.clone()).unwrap().open().unwrap();

    println!("\nDevice Found: {} : {}", device.name, device.desc.unwrap());
    println!("Sniffing network...\n");

    // Sniff packets
    while let Ok(packet) = cap.next_packet() {
        
        // Create new byte iterator
        let mut frame = NextInts::new(packet.data);

        println!("\n PACKET - size: {}", packet.header.len);
        println!(" └ ETHERNET II: ");

        // Get 6 firsts bytes (@MAC Destination) and display it
        let dest_mac = frame.next_ints(6);

        println!("   ├ DEST MAC: {}:{}:{}:{}:{}:{}",
            format!("{:02X}", dest_mac[0]),
            format!("{:02X}", dest_mac[1]),
            format!("{:02X}", dest_mac[2]),
            format!("{:02X}", dest_mac[3]),
            format!("{:02X}", dest_mac[4]),
            format!("{:02X}", dest_mac[5])
        );

        // ...
        let src_mac = frame.next_ints(6);

        println!("   ├ SRC MAC: {}:{}:{}:{}:{}:{}",
            format!("{:02X}", src_mac[0]),
            format!("{:02X}", src_mac[1]),
            format!("{:02X}", src_mac[2]),
            format!("{:02X}", src_mac[3]),
            format!("{:02X}", src_mac[4]),
            format!("{:02X}", src_mac[5])
        );

        let ether_type = frame.next_ints(2);

        println!("   └ ETHER TYPE: {}{}",
            format!("{:02X}", ether_type[0]),
            format!("{:02X}", ether_type[1])
        );

        // If EtherType is 0x0800 for IPv4
        if ether_type == [0x08, 0x00] {
            println!("     └ IPv4: ");

            let version_ihl = frame.next_ints(1);

            println!("       ├ VERSION/IHL: {}",
                format!("{:02X}", version_ihl[0])
            );

            let tos = frame.next_ints(1);

            println!("       ├ TOS: {}",
                format!("{:02X}", tos[0])
            );

            let total_length = frame.next_ints(2);

            println!("       ├ TOTAL LENGTH: {}",
                u16::from_be_bytes([total_length[0], total_length[1]])
            );

            let identification = frame.next_ints(2);

            println!("       ├ IDENTIFICATION: {}{}",
                format!("{:02X}", identification[0]),
                format!("{:02X}", identification[0])
            );

            let flags_fragment_offset = frame.next_ints(2);

            println!("       ├ FLAGS/FRAGMENT OFFSET: {}{}",
                format!("{:02X}", flags_fragment_offset[0]),
                format!("{:02X}", flags_fragment_offset[0])
            );

            let ttl = frame.next_ints(1);

            println!("       ├ TTL: {}",
                ttl[0]
            );

            let protocol = frame.next_ints(1);

            println!("       ├ PROTOCOL: {}",
                format!("{:02X}", protocol[0])
            );

            let header_checksum = frame.next_ints(2);

            println!("       ├ HEADER CHECKSUM: {}{}",
                format!("{:02X}", header_checksum[0]),
                format!("{:02X}", header_checksum[1])
            );

            let src_addr = frame.next_ints(4);

            println!("       ├ SOURCE ADDRESS: {}.{}.{}.{}",
                src_addr[0],
                src_addr[1],
                src_addr[2],
                src_addr[3]
            );

            let dest_addr = frame.next_ints(4);

            println!("       └ DESTINATION ADDRESS: {}.{}.{}.{}",
                dest_addr[0],
                dest_addr[1],
                dest_addr[2],
                dest_addr[3]
            );
        }
    }
}
