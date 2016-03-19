use std::error;
use std::io;
use std::io::prelude::*;
use byteorder;
use bit_vec::BitVec;
use std::net::{Ipv4Addr,IpAddr, Ipv6Addr};
use std::fmt;
use std::string;
use byteorder::{BigEndian, ReadBytesExt};

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    ByteOrder(byteorder::Error),
    UnexpectedValue,
    WrongType
}

pub type ASN1Result<T> = Result<T, Error>;
pub type ObjectIdentifier = Box<[u32]>;

type ASN1Reader<'a> = io::Cursor<&'a [u8]>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::WrongType => write!(f, "WrongType"),
            Error::ByteOrder(ref e) => write!(f, "{}", e),
            Error::UnexpectedValue => write!(f, "UnexpectedValue"),
            Error::Io(ref e) => write!(f, "{}", e)
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::WrongType => "wrong type!",
            Error::ByteOrder(ref e) => e.description(),
            Error::Io(ref e) => e.description(),
            Error::UnexpectedValue => "unexpected value"
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(_: string::FromUtf8Error) -> Error {
        Error::WrongType
    }
}

impl From<byteorder::Error> for Error {
    fn from(e: byteorder::Error) -> Error {
        Error::ByteOrder(e)
    }
}

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

    /* PDU Types */
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

impl ASN1Type {
    fn from(b: u8) -> Result<ASN1Type, Error> {
        use self::ASN1Type::*;

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
            _ => return Err(Error::WrongType)
        })
    }
}

pub type Sequence = Box<[ASN1Value]>;

#[derive(Debug, Clone)]
pub enum ASN1Value {
    EndOfContents,
    Sequence(Sequence),
    Boolean(bool),
    Integer(i64),
    BitString(BitVec),
    OctetString(String),
    Null,
    ObjectIdentifier(ObjectIdentifier),
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
    // maybe this should just be a generic ASN1Value and let the callers decode it to a trap
    Trap(Sequence)
}


impl ASN1Value {
    pub fn as_oid(self) -> Result<ObjectIdentifier, Error> {
        match self {
            ASN1Value::ObjectIdentifier(a) => Ok(a),
            _ => Err(Error::WrongType)
        }
    }

    pub fn as_ipaddr(self) -> Result<IpAddr, Error> {
        match self {
            ASN1Value::IPAddress(addr) => Ok(addr),
            _ => Err(Error::WrongType)
        }
    }

    pub fn as_bool(self) -> Result<bool, Error> {
        match self {
            ASN1Value::Boolean(b) => Ok(b),
            _ => Err(Error::WrongType)
        }
    }

    pub fn as_i64(self) -> Result<i64, Error> {
        match self {
            ASN1Value::Integer(i) => Ok(i),
            _ => Err(Error::WrongType)
        }
    }

    pub fn as_u32(self) -> Result<u32, Error> {
        match self {
            ASN1Value::Integer(x) => Ok(x as u32),
            ASN1Value::TimeTicks(x) => Ok(x),
            _ => Err(Error::WrongType)
        }
    }

    pub fn as_string(self) -> Result<String, Error> {
        match self {
            ASN1Value::OctetString(s) => Ok(s),
            _ => Err(Error::WrongType)
        }
    }

    pub fn as_sequence(self) -> Result<Sequence, Error> {
        match self {
            ASN1Value::Sequence(v) => Ok(v),
            ASN1Value::Trap(v) => Ok(v),
            _ => Err(Error::WrongType)
        }
    }
}

fn read_tag_value(reader: &mut ASN1Reader) -> Result<(ASN1Type, usize), Error> {
    let asn_type = try!(read_byte(reader).and_then(ASN1Type::from));
    let length = try!(read_length(reader));
    Ok((asn_type, length))
}

fn read_sequence(c: &mut io::Cursor<&[u8]>, len: usize) -> Result<Sequence, Error> {
    let mut out = vec![];
    let start = c.position();
    while ((c.position() - start) as usize) < len {
        let val = try!(decode_value(c));
        out.push(val);
    }
    Ok(out.into_boxed_slice())
}

pub fn decode_value(c: &mut io::Cursor<&[u8]>) -> Result<ASN1Value, Error> {
    use self::ASN1Type::*;

    let (asn_type, length) = try!(read_tag_value(c));
    println!("{:?} length: {}", asn_type, length);

    match asn_type {
        Sequence => {
            Ok(ASN1Value::Sequence(try!(read_sequence(c, length))))
        }
        Integer => {
            let val = try!(read_integer(c, length));
            Ok(ASN1Value::Integer(val))
        },
        OctetString => {
            let mut s = vec![0 ; length];
            try!(c.read_exact(&mut s));
            let s = try!(String::from_utf8(s));
            Ok(ASN1Value::OctetString(s))
        }
        Null => {
            Ok(ASN1Value::Null)
        },
        ObjectIdentifier => {
            read_oid(c, length).map(|x| ASN1Value::ObjectIdentifier(x))
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
            Ok(ASN1Value::Trap(try!(read_sequence(c, length))))
        },
        _ => {
            Err(Error::WrongType)
        }
    }
}

#[inline]
fn read_byte(reader: &mut ASN1Reader) -> Result<u8, Error> {
    reader.read_u8().map_err(Error::ByteOrder)
}

fn read_length(reader: &mut ASN1Reader) -> Result<usize, Error> {
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

fn read_integer(reader: &mut ASN1Reader, len: usize) -> Result<i64, Error> {
    let mut v = 0;

    for _ in 0..len {
        v <<= 8;
        v += try!(read_byte(reader)) as i64;
    }
    Ok(v)
}

fn read_base128int(reader: &mut ASN1Reader) -> Result<u32, Error> {
    // TODO: review this code
    let mut r = 0;
    loop {
        if r > 4 {
            return Err(Error::UnexpectedValue)
        }
        r <<= 8;
        let b = try!(read_byte(reader));
        r += (b & 0x7f) as u32;
        if b & 0x80 == 0 {
            break
        }
    }
    Ok(r)
}

fn read_oid(r: &mut ASN1Reader, len: usize) -> Result<ObjectIdentifier, Error> {
    // TODO: review this code
    let mut oid = Vec::new();

    let v = try!(read_byte(r));
    oid.push( (v/40) as u32);
    oid.push( (v % 40) as u32);

    let start = r.position();

    while ((r.position() - start) as usize) < len {
        let val = try!(read_base128int(r));
        oid.push(val);
    }
    Ok(oid.into_boxed_slice())
}


fn read_ip_address(reader: &mut ASN1Reader, size: usize) -> ASN1Result<IpAddr> {
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
            Err(Error::UnexpectedValue)
        }
    }
}

