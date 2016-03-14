#![allow(dead_code)]
extern crate byteorder;
extern crate libc;
extern crate bit_vec;

#[derive(Debug)]
enum ASN1Type {
    EndOfContents = 0,
    Boolean = 0x1,
    Integer = 0x2,
    BitString = 0x3,
    OctetString = 0x4,
    Null = 0x5,
    ObjectIdentifier = 0x6,
    ObjectDescription = 0x7,
    Sequence  = 0x30,
    IPAddress = 0x40,
    Counter32 = 0x41,
    Gauge32 = 0x42,
    TimeTicks = 0x43,
    Opaque = 0x44,
    NsapAddress = 0x45,
    Counter64 = 0x46,
    Uinteger32 = 0x47,
    NoSuchObject = 0x80,
    NoSuchInstance = 0x81,
    EndOfMibView = 0x82,
    GetRequest = 0xa0,
    GetNextRequest = 0xa1,
    GetResponse = 0xa2,
    SetRequest = 0xa3,
    Trap = 0xa4,
    GetBulkRequest = 0xa5,
    InformRequest = 0xa6,
    SnmpV2Trap = 0xa7,
    Report = 0xa8
}

use std::error::Error;
type SnmpError = Box<Error + Send + Sync>;

use std::io::prelude::*;
use std::io;
#[derive(Debug)]
enum PDUType {
}

impl ASN1Type {
    fn from(b: u8) -> Result<ASN1Type, SnmpError> {
        use ASN1Type::*;

        Ok(match b {
            0 => EndOfContents,
            1 => Boolean,
            2 => Integer,
            3 => BitString,
            4 => OctetString,
            5 => Null,
            6 => ObjectIdentifier,
            7 => ObjectDescription,
            0x30 => Sequence,
            0x40 => IPAddress,
            0x41 => Counter32,
            0x42 => Gauge32,
            0x43 => TimeTicks,
            0x45 => NsapAddress,
            0x46 => Counter64,
            0x47 => Uinteger32,
            0x80 => NoSuchObject,
            0x81 => NoSuchInstance,
            0x82 => EndOfMibView,
            0xa0 => GetRequest,
            0xa1 => GetNextRequest,
            0xa2 => GetResponse,
            0xa3 => SetRequest,
            0xa4 => Trap,
            0xa5 => GetBulkRequest,
            0xa6 => InformRequest,
            0xa7 => SnmpV2Trap,
            0xa8 => Report,
            _ => return Err(From::from(format!("invalid type: {}", b)))
        })
    }
}

use bit_vec::BitVec;
use std::net::*;

#[derive(Debug, Clone)]
pub enum ASN1Value {
    EndOfContents,
    Sequence(Vec<ASN1Value>),
    Boolean(bool),
    Integer(i64),
    BitString(BitVec),
    OctetString(String),
    Null,
    ObjectIdentifier(Vec<u32>),
    ObjectDescription(String),
    IPAddress(IpAddr),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
    Opaque(Vec<u8>),
    NsapAddress(Vec<u8>),
    Counter64(u64),
    Uinteger32(u32),
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
    Trap(Trap)
}

impl ASN1Value {
    fn as_oid(self) -> Result<Vec<u32>, SnmpError> {
        match self {
            ASN1Value::ObjectIdentifier(a) => Ok(a),
            _ => Err(From::from(format!("wrong type: {:?}", self)))
        }
    }

    fn as_ipaddr(self) -> Result<IpAddr, SnmpError> {
        match self {
            ASN1Value::IPAddress(addr) => Ok(addr),
            _ => Err(From::from("wrong type"))
        }
    }

    fn as_u32(self) -> Result<u32, SnmpError> {
        match self {
            ASN1Value::Integer(x) => Ok(x as u32),
            ASN1Value::TimeTicks(x) => Ok(x),
            _ => Err(From::from(format!("wrong type: {:?}", self)))
        }
    }

    fn as_sequence(self) -> Result<Vec<ASN1Value>, SnmpError> {
        match self {
            ASN1Value::Sequence(v) => Ok(v),
            _ => Err(From::from(format!("wrong type: {:?}", self)))
        }
    }
}

#[derive(Debug)]
enum SnmpVersion {
    Version1 = 0x0,
    Version2c = 0x1,
    Version3 = 0x3
}


fn read_byte(reader: &mut Read) -> Result<u8, SnmpError> {
    let mut b = [0u8 ; 1 ];

    try!(reader.read_exact(&mut b));
    Ok(b[0])
}

fn read_length(reader: &mut Read) -> Result<usize, SnmpError> {
    let length = try!(read_byte(reader));

    if length < 127 {
        Ok(length as usize)
    } else {
        let num_octets = length & 127;
        let mut ex_length: usize = 0;
        for _ in 0..num_octets {
            ex_length <<= 8;
            ex_length += try!(read_byte(reader)) as usize;
        }
        Ok(ex_length)
    }
}

fn read_integer(reader: &mut Read, len: usize) -> Result<i64, SnmpError> {
    let mut v = 0;

    for _ in 0..len {
        v <<= 8;
        v += try!(read_byte(reader)) as i64;
    }
    Ok(v)
}

fn read_base128int(reader: &mut Read) -> Result<(u32, usize), SnmpError> {
    let mut r = 0;
    let mut bytes_read = 0;
    loop {
        if r > 4 {
            return Err(From::from("too big"))
        }
        r <<= 8;
        let b = try!(read_byte(reader));
        bytes_read += 1;
        r += (b & 0x7f) as u32;
        if b & 0x80 == 0 {
            break
        }
    }
    Ok((r, bytes_read))
}

fn parse_oid(r: &mut Read, len: usize) -> Result<Vec<u32>, SnmpError> {
    let mut oid = Vec::new();

    let v = try!(read_byte(r));
    oid.push( (v/40) as u32);
    oid.push( (v % 40) as u32);

    let mut bytes_read = 1;
    while bytes_read < len {
        let (val, bytes) = try!(read_base128int(r));
        bytes_read += bytes;
        oid.push(val);
    }
    Ok(oid)
}

use byteorder::{BigEndian, ReadBytesExt};

fn read_ip_address(reader: &mut Read, size: usize) -> Result<IpAddr, SnmpError> {
    match size {
        4 => {
            let mut bytes = [0 ; 4];
            try!(reader.read_exact(&mut bytes));

            Ok(IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])))
        }
        16 => {
            let mut elements = [0 ; 8];
            for i in 0..8 {
                let d = try!(reader.read_u16::<BigEndian>());
                elements[i] = d;
            }
            Ok(IpAddr::V6(Ipv6Addr::new(elements[0], elements[1],
                                        elements[2], elements[3],
                                        elements[4], elements[5],
                                        elements[6], elements[7])))
        },
        _ => {
            Err(From::from(format!("invalid ip size {}", size)))
        }
    }
}

fn read_tag_value(reader: &mut Read) -> Result<(ASN1Type, usize), SnmpError> {
    let asn_type = try!(read_byte(reader).and_then(ASN1Type::from));
    let length = try!(read_length(reader));
    Ok((asn_type, length))
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
    enterprise_oid: Vec<u32>,
    agent_address: IpAddr,
    generic: GenericTrap,
    specific: u32,
    time_ticks: u32,
    variables: Vec<(ASN1Value, ASN1Value)>
}

fn decode_value(c: &mut io::Cursor<&[u8]>) -> Result<ASN1Value, SnmpError> {
    use ASN1Type::*;

    let asn_type = try!(read_byte(c).and_then(ASN1Type::from));
    let length = try!(read_length(c));

    println!("{:?} length: {}", asn_type, length);

    match asn_type {
        Sequence => {
            let mut out = Vec::new();
            while (c.position() as usize) < length {
                let val = try!(decode_value(c));
                out.push(val)
            }
            Ok(ASN1Value::Sequence(out))
        }
        Integer => {
            let val = try!(read_integer(c, length));
            println!("read an Integer {}", val);
            Ok(ASN1Value::Integer(val))
        },
        OctetString => {
            let mut s = vec![0u8 ; length];
            try!(c.read_exact(&mut s));
            let s = try!(String::from_utf8(s));
            Ok(ASN1Value::OctetString(s))
        }
        Null => {
            Ok(ASN1Value::Null)
        },
        ObjectIdentifier => {
            parse_oid(c, length).map(|x| ASN1Value::ObjectIdentifier(x))
        }
        IPAddress => {
            read_ip_address(c, length).map(|x| ASN1Value::IPAddress(x))
        },
        Counter32 => {
            read_integer(c, length).map(|x| ASN1Value::Counter32(x as u32))
        },
        Gauge32 => {
            read_integer(c, length).map(|x| ASN1Value::Gauge32(x as u32))
        },
        TimeTicks => {
            read_integer(c, length).map(|x| ASN1Value::TimeTicks(x as u32))
        }
        Counter64 => {
            read_integer(c, length).map(|x| ASN1Value::Counter64(x as u64))
        }
        Opaque => {
            let mut buf = vec![0 ; length];
            try!(c.read_exact(&mut buf));
            Ok(ASN1Value::Opaque(buf))
        }
        NoSuchObject => {
            Ok(ASN1Value::NoSuchObject)
        },
        NoSuchInstance => {
            Ok(ASN1Value::NoSuchInstance)
        },
        EndOfMibView => {
            Ok(ASN1Value::EndOfMibView)
        },
        EndOfContents => {
            Ok(ASN1Value::EndOfContents)
        },
        Trap => {
            let start = c.position();
            let oid = try!(decode_value(c).and_then(|x| x.as_oid()));
            let addr = try!(decode_value(c).and_then(|x| x.as_ipaddr()));
            let gen = try!(decode_value(c).and_then(|x| x.as_u32()).and_then(|x| GenericTrap::new(x)));
            let spec = try!(decode_value(c).and_then(|x| x.as_u32()));
            let ticks = try!(decode_value(c).and_then(|x| x.as_u32()));

            let mut vars = vec![];

            while ((c.position() - start) as usize) < length {
                let vbl = try!(decode_value(c).and_then(|x| x.as_sequence()));
                if !vbl.is_empty() {
                    vars.push((vbl[0].clone(), vbl[1].clone()));
                }
            }

            let trap = ::Trap{
                enterprise_oid: oid,
                agent_address: addr,
                generic: gen,
                specific: spec,
                time_ticks: ticks,
                variables: vars
            };

            Ok(ASN1Value::Trap(trap))
        },
        _ => {
            Err(From::from(format!("invalid type: {:?}", asn_type)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::decode_value;
    use std::io;
    #[test]
    fn trap_test() {
        let bytes = include_bytes!("../test/fixtures/snmpv1-trap-coldStart.bin");
        let mut c = io::Cursor::new(&bytes[..]);
        let v = decode_value(&mut c).unwrap();
        println!("v = {:?}", v);
        assert_eq!(0, 1);
    }
}
