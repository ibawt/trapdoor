#![allow(dead_code)]
extern crate byteorder;
extern crate bit_vec;
extern crate libc;

use std::error::Error;
use std::io;
use std::net::IpAddr;

mod asn1;

pub type SnmpError = Box<Error + Send + Sync>;


#[derive(Debug, Clone, Copy)]
enum SnmpVersion {
    Version1 = 0x0,
    Version2c = 0x1,
    Version3 = 0x3
}

#[derive(Debug, Clone)]
pub enum SnmpPacket {
    V1(SnmpV1Packet)
}

#[derive(Debug, Clone)]
pub struct SnmpV1Packet {
    community: String,
    value: SnmpV1PDU
}

impl SnmpPacket {
    fn new(b: &[u8]) -> Result<SnmpPacket, SnmpError> {
        let mut c = io::Cursor::new(b);

        let decoded = try!(asn1::decode_value(&mut c));

        let sequence = try!(decoded.as_sequence());
        let version = try!(sequence[0].clone().as_u32());
        let community = try!(sequence[1].clone().as_string());

        match version {
            0 => Ok(SnmpPacket::V1( SnmpV1Packet{
                community: community,
                value: try!(SnmpV1PDU::new(sequence[2].clone()))})),
            _ => Err(From::from("blah"))
        }
    }
}


#[derive(Debug, Clone)]
pub enum SnmpV1PDU {
    Trap(Trap)
}

impl SnmpV1PDU {
    fn new(a: asn1::ASN1Value) -> Result<SnmpV1PDU, SnmpError> {
        match a {
            asn1::ASN1Value::Trap(a) => {
                Ok(SnmpV1PDU::Trap(try!(decode_trap(&a))))
            },
            _ => Err(From::from("invalid type for pdu"))
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum GenericTrap {
    ColdStart = 0,
    WarmStart = 1,
    LinkDown = 2,
    LinkUp = 3,
    AuthenticationFailure = 4,
    EgpNeighborLoss = 5,
    EnterpriseSpecific = 6
}

impl GenericTrap {
    fn new(b: u32) -> Result<GenericTrap, SnmpError> {
        use GenericTrap::*;
        Ok(match b {
            0 => ColdStart,
            1 => WarmStart,
            2 => LinkDown,
            3 => LinkUp,
            4 => AuthenticationFailure,
            5 => EgpNeighborLoss,
            6 => EnterpriseSpecific,
            _ => return Err(From::from("idk"))
        })
    }
}

#[derive(Debug, Clone)]
pub struct Trap {
    enterprise_oid: asn1::ObjectIdentifier,
    agent_address: IpAddr,
    generic: GenericTrap,
    specific: u32,
    time_ticks: u32,
    variables: Box<[asn1::ASN1Value]>
}

fn decode_trap(v: &[asn1::ASN1Value]) -> Result<Trap, SnmpError> {
    if v.len() < 6 {
        return Err(From::from("invalid length"))
    }
    let oid = try!(v[0].clone().as_oid());
    let addr = try!(v[1].clone().as_ipaddr());
    let trap = try!(GenericTrap::new(try!(v[2].clone().as_u32())));
    let specific = try!(v[3].clone().as_u32());
    let time_ticks = try!(v[4].clone().as_u32());
    let vars = try!(v[5].clone().as_sequence());

    Ok(Trap{
        enterprise_oid: oid,
        agent_address: addr,
        generic: trap,
        specific: specific,
        time_ticks: time_ticks,
        variables: vars
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trap_test() {
        let bytes = include_bytes!("../test/fixtures/snmpv1-trap-coldStart.bin");
        let v = SnmpPacket::new(bytes).unwrap();
        println!("v = {:?}", v);
        assert_eq!(0, 1);
    }
}
