use std::io;
use std::net::IpAddr;
use std::error;
use std::fmt;

use asn1;

#[derive(Debug)]
pub enum SnmpError {
    ASN1Error(asn1::Error),
    WrongType,
    Generic(String)
}

impl fmt::Display for SnmpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SnmpError::ASN1Error(ref e) => write!(f, "{}", e),
            SnmpError::WrongType => write!(f, "wrong type"),
            SnmpError::Generic(ref e) => write!(f, "{}", e)
        }
    }
}

impl error::Error for SnmpError {
    fn description(&self) -> &str {
        match *self {
            SnmpError::ASN1Error(ref e) => e.description(),
            SnmpError::WrongType => "wrong type",
            SnmpError::Generic(ref s) => s
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            SnmpError::ASN1Error(ref e) => e.cause(),
            _ => None
        }
    }
}

impl<'a> From<&'a str> for SnmpError {
    fn from(e: &'a str) -> SnmpError {
        SnmpError::Generic(e.to_owned())
    }
}

impl From<asn1::Error> for SnmpError {
    fn from(e: asn1::Error) -> SnmpError {
        SnmpError::ASN1Error(e)
    }
}

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
    pub community: String,
    pub pdu: SnmpV1PDU
}

impl SnmpPacket {
    pub fn new(b: &[u8]) -> Result<SnmpPacket, SnmpError> {
        let mut c = io::Cursor::new(b);

        let decoded = try!(asn1::decode_value(&mut c));
        let sequence = try!(decoded.as_sequence());

        let version = try!(sequence[0].clone().as_u32());
        let community = try!(sequence[1].clone().as_string());

        match version {
            0 => Ok(SnmpPacket::V1( SnmpV1Packet{
                community: community,
                pdu: try!(SnmpV1PDU::new(sequence[2].clone()))})),
            _ => Err(From::from("blah"))
        }
    }


    pub fn as_v1(self) -> Result<SnmpV1Packet, SnmpError> {
        match self {
            SnmpPacket::V1(p) => Ok(p),
            // _ => Err(From::from("invalid type"))
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

    fn as_trap(self) -> Result<Trap, SnmpError> {
        match self {
            SnmpV1PDU::Trap(t) => Ok(t),
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
        use self::GenericTrap::*;
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

#[derive(Debug, PartialEq, Clone)]
pub enum ErrorStatus {
    NoError = 0,
    TooBig = 1,
    NoSuchName = 2,
    BadValue = 3,
    ReadOnly = 4,
    GenErr = 5
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
    use asn1::*;
    use std::net::*;

    #[test]
    fn trap_test() {
        let bytes = include_bytes!("../test/fixtures/snmpv1-trap-linkDown.bin");
        let v = SnmpPacket::new(bytes).unwrap();

        let v1pkt = v.as_v1().unwrap();
        assert_eq!(v1pkt.community, "public");

        let trap = v1pkt.pdu.as_trap().unwrap();
        assert!(oid_equals(&[1,3,6,1,6, 3], &trap.enterprise_oid));
        assert_eq!(trap.agent_address, IpAddr::V4(Ipv4Addr::new(23,3,3,4)));
        assert_eq!(trap.generic, GenericTrap::LinkDown);
    }
}
