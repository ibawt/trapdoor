#![allow(dead_code)]
extern crate byteorder;
extern crate bit_vec;
extern crate libc;
extern crate crossbeam;

mod asn1;
mod snmp;
mod server;

fn main() {
    server::run_server("127.0.0.1:1062");
}
