use std::net::*;
use snmp::*;
use crossbeam;

pub struct Server {
    num_packets: u64
}

impl Server {
    fn new() -> Server {
        Server {
            num_packets: 0
        }
    }

    fn handle_packet(&mut self, p: SnmpPacket) {
        self.num_packets += 1;
        match p {
            SnmpPacket::V1(v1) => {
                match v1.pdu {
                    SnmpV1PDU::Trap(trap) => {
                        println!("trap!");
                    }
                }
            }
        }
    }
}
use std::sync::*;

pub fn run_server(addr: &str) {
    let server = Mutex::new(Server::new());
    let queue = crossbeam::sync::MsQueue::new();
    crossbeam::scope(|scope| {
        scope.spawn(|| {
            let mut bytes = [0; 4096];
            let socket = UdpSocket::bind(addr).unwrap();
            loop {
                let (num_bytes, _) = match socket.recv_from(&mut bytes) {
                    Ok(x) => x,
                    Err(e) => {
                        println!("socket error: {:?}", e);
                        continue;
                    }
                };
                let pkt = match SnmpPacket::new(&bytes[..num_bytes]) {
                    Ok(p) => p,
                    Err(e) => {
                        println!("snmp packet parse error: {:?}", e);
                        continue;
                    }
                };
                println!("pushing to queue");
                queue.push(pkt);
            }
        });
        for _ in 0..2 {
            scope.spawn(|| {
                loop {
                    let val = queue.pop();
                    if let Ok(mut s) = server.try_lock() {
                        s.handle_packet(val);
                    }
                }
            });
        }
    });
}
