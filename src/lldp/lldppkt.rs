/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 *  Author: Rayhaan Jaufeerally <rayhaan@rayhaan.ch>
 *
 *  LLDP packet parser for the protocol defined in IEEE 802.1AB-2016.
 */

/// lldppkt is an implementation of the wire format of IEEE 802.1AB-2016
use crate::pktparser;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::fmt::Formatter;

use std::convert::TryInto;
use std::io::ErrorKind;

pub trait ToWire {
    fn to_wire(&self) -> Result<Vec<u8>, std::io::Error>;
}

pub trait FromWire {
    fn from_wire(buf: &mut pktparser::Buffer<'_>) -> Result<Self, pktparser::ParseError>
    where
        Self: Sized;
}

/// LLDPPacket represents a LLDP PDU that can be read from / written to the wire.
/// LLDP PDUs are simply a concatenation of TLVs in an Ethernet frame with type 0x88cc.
/// At the end of the PDU there is an empty TLV header.
/// The first three TLVs must be: ChassisID, PortID and TTL.
#[derive(Debug)]
pub struct LLDPPacket {
    pub tlvs: Vec<LLDPTLV>,
}

impl LLDPPacket {
    fn validate_format(&self) -> Result<(), std::io::Error> {
        if self.tlvs.len() < 4 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "At least 4 mandatory TLVs are required in an LLDP PDU.",
            ));
        }

        // Safe to unwrap four elements since we checked above.
        let first: &LLDPTLV = self.tlvs.get(0).unwrap();
        let second: &LLDPTLV = self.tlvs.get(1).unwrap();
        let third: &LLDPTLV = self.tlvs.get(2).unwrap();
        let last: &LLDPTLV = self.tlvs.get(self.tlvs.len() - 1).unwrap();

        if !matches!(first, LLDPTLV::ChassisID(_)) {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("Expected first TLV to be ChassisID but got {}", first),
            ));
        }
        if !matches!(second, LLDPTLV::PortID(_)) {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("Expected second TLV to be PortID but got {}", second),
            ));
        }
        if !matches!(third, LLDPTLV::TTL(_)) {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("Expected third TLV to be TTL but got {}", third),
            ));
        }
        if !matches!(last, LLDPTLV::EndOfLLDPPDU()) {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("Expected last TLV to be EndOfLLDPPDU but got {}", last),
            ));
        }

        Ok(())
    }
}

impl ToWire for LLDPPacket {
    fn to_wire(&self) -> Result<Vec<u8>, std::io::Error> {
        self.validate_format()?;
        let mut pdu = Vec::new();

        for tlv in &self.tlvs {
            pdu.append(&mut tlv.to_wire()?);
        }

        Ok(pdu)
    }
}

impl FromWire for LLDPPacket {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        let mut tlvs = Vec::new();
        while buf.remaining() > 0 {
            tlvs.push(LLDPTLV::from_wire(buf)?);
            if matches!(tlvs[tlvs.len() - 1], LLDPTLV::EndOfLLDPPDU()) {
                return Ok(LLDPPacket { tlvs });
            }
        }
        Err(pktparser::ParseError::InvalidArgument(
            "Malformed LLDP packet: missing End of LLDP PDU TLV".to_string(),
        ))
    }
}

impl std::fmt::Display for LLDPPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "LLDP [\n")?;
        for tlv in &self.tlvs {
            write!(f, "\t{}\n", tlv)?;
        }
        write!(f, "]")
    }
}

#[derive(Debug)]
pub struct LLDPTLVHeader {
    pub r#type: u8,  // 7 bits on the wire.
    pub length: u16, // 9 bits on the wire
}

impl ToWire for LLDPTLVHeader {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        let out: u16 = ((self.r#type as u16) << 9) as u16 | (0b0000_0001_1111_1111 & self.length);
        let mut vec = vec![];
        WriteBytesExt::write_u16::<BigEndian>(&mut vec, out)?;
        Ok(vec)
    }
}

impl FromWire for LLDPTLVHeader {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        let input = buf
            .get_be16()
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;
        let r#type = ((input & 0b1111_1110_0000_0000) >> 9) as u8;
        let length = input & 0b0000_0001_1111_1111;

        Ok(LLDPTLVHeader { r#type, length })
    }
}

#[derive(Debug)]
pub enum LLDPTLV {
    /// 8.5.2
    ChassisID(ChassisID),
    /// 8.5.3
    PortID(PortID),
    /// 8.5.4
    TTL(TTL),
    /// 8.5.5
    PortDescription(PortDescription),
    /// 8.5.6
    SystemName(SystemName),
    /// 8.5.7
    SystemDescription(SystemDescription),
    /// 8.5.8
    SystemCapabilities(SystemCapabilities),
    /// 8.5.9
    ManagementAddress(ManagementAddress),

    OrganizationSpecific(OrganizationSpecific),

    EndOfLLDPPDU(),
}

impl ToWire for LLDPTLV {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        match self {
            Self::ChassisID(tlv) => tlv.to_wire(),
            Self::PortID(tlv) => tlv.to_wire(),
            Self::TTL(tlv) => tlv.to_wire(),
            Self::PortDescription(tlv) => tlv.to_wire(),
            Self::SystemName(tlv) => tlv.to_wire(),
            Self::SystemDescription(tlv) => tlv.to_wire(),
            Self::SystemCapabilities(tlv) => tlv.to_wire(),
            Self::ManagementAddress(tlv) => tlv.to_wire(),
            Self::OrganizationSpecific(tlv) => tlv.to_wire(),
            Self::EndOfLLDPPDU() => Ok(vec![0u8, 0u8]),
        }
    }
}

impl FromWire for LLDPTLV {
    fn from_wire(buf: &mut pktparser::Buffer<'_>) -> Result<Self, pktparser::ParseError>
    where
        Self: Sized,
    {
        let t = ((buf
            .peek_u8()
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?)
            & 0b1111_1110)
            >> 1;

        match t {
            0 => Ok(Self::EndOfLLDPPDU()),
            1 => Ok(LLDPTLV::ChassisID(ChassisID::from_wire(buf)?)),
            2 => Ok(LLDPTLV::PortID(PortID::from_wire(buf)?)),
            3 => Ok(LLDPTLV::TTL(TTL::from_wire(buf)?)),
            4 => Ok(LLDPTLV::PortDescription(PortDescription::from_wire(buf)?)),
            5 => Ok(LLDPTLV::SystemName(SystemName::from_wire(buf)?)),
            6 => Ok(LLDPTLV::SystemDescription(SystemDescription::from_wire(
                buf,
            )?)),
            7 => Ok(LLDPTLV::SystemCapabilities(SystemCapabilities::from_wire(
                buf,
            )?)),
            8 => Ok(LLDPTLV::ManagementAddress(ManagementAddress::from_wire(
                buf,
            )?)),
            127 => Ok(LLDPTLV::OrganizationSpecific(
                OrganizationSpecific::from_wire(buf)?,
            )),
            o => Err(pktparser::ParseError::InvalidArgument(format!(
                "Unknown LLDP TLV type: {}",
                o
            ))),
        }
    }
}

impl std::fmt::Display for LLDPTLV {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChassisID(tlv) => tlv.fmt(f),
            Self::PortID(tlv) => tlv.fmt(f),
            Self::TTL(tlv) => tlv.fmt(f),
            Self::PortDescription(tlv) => tlv.fmt(f),
            Self::SystemName(tlv) => tlv.fmt(f),
            Self::SystemDescription(tlv) => tlv.fmt(f),
            Self::SystemCapabilities(tlv) => tlv.fmt(f),
            Self::ManagementAddress(tlv) => tlv.fmt(f),
            Self::OrganizationSpecific(tlv) => tlv.fmt(f),
            Self::EndOfLLDPPDU() => write!(f, "End of LLDPPDU"),
        }
    }
}

#[derive(Debug)]
pub struct ChassisID {
    r#type: ChassisIDType,
    identifier: Vec<u8>,
}

impl ToWire for ChassisID {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        let mut value: Vec<u8> = Vec::new();
        value.append(&mut self.r#type.to_wire()?);
        value.append(&mut self.identifier.clone());
        let header = LLDPTLVHeader {
            r#type: 1,
            length: 1 + self.identifier.len() as u16,
        };
        let mut output = header.to_wire()?;
        output.append(&mut value);
        Ok(output)
    }
}

impl FromWire for ChassisID {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        let header = LLDPTLVHeader::from_wire(buf)?;
        if header.r#type != 1 {
            return Err(pktparser::ParseError::InvalidArgument(format!(
                "Want type 1 for ChassisID TLV but got {}",
                header.r#type,
            )));
        }

        let mut payload = buf
            .get_buffer(header.length.into())
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;

        let subtype = ChassisIDType::from_wire(&mut payload)?;

        let identifier: Vec<u8> = payload
            .get_vec(payload.remaining())
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;

        Ok(ChassisID {
            r#type: subtype,
            identifier,
        })
    }
}

impl std::fmt::Display for ChassisID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ChassisID type: {} value: {:02x?}",
            self.r#type, self.identifier
        )
    }
}

#[derive(Debug)]
pub enum ChassisIDType {
    ChassisComponent,
    InterfaceAlias,
    PortComponent,
    MacAddress,
    NetworkAddress,
    InterfaceName,
    Local,
}

impl FromWire for ChassisIDType {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<ChassisIDType, pktparser::ParseError> {
        Ok(
            match buf
                .get_u8()
                .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?
            {
                1 => Self::ChassisComponent,
                2 => Self::InterfaceAlias,
                3 => Self::PortComponent,
                4 => Self::MacAddress,
                5 => Self::NetworkAddress,
                6 => Self::InterfaceName,
                7 => Self::Local,
                other => {
                    return Err(pktparser::ParseError::InvalidArgument(format!(
                        "Unknown ChassisIDType {}",
                        other
                    )))
                }
            },
        )
    }
}

impl ToWire for ChassisIDType {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        Ok(match self {
            Self::ChassisComponent => vec![1],
            Self::InterfaceAlias => vec![2],
            Self::PortComponent => vec![3],
            Self::MacAddress => vec![4],
            Self::NetworkAddress => vec![5],
            Self::InterfaceName => vec![6],
            Self::Local => vec![7],
        })
    }
}

impl std::fmt::Display for ChassisIDType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            Self::ChassisComponent => write!(f, "ChassisComponent"),
            Self::InterfaceAlias => write!(f, "InterfaceAlias"),
            Self::PortComponent => write!(f, "PortComponent"),
            Self::MacAddress => write!(f, "MacAddress"),
            Self::NetworkAddress => write!(f, "NetworkAddress"),
            Self::InterfaceName => write!(f, "InterfaceName"),
            Self::Local => write!(f, "Local"),
        }
    }
}

#[derive(Debug)]
pub struct PortID {
    pub r#type: PortIDType,
    pub identifier: Vec<u8>,
}

impl FromWire for PortID {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        let header = LLDPTLVHeader::from_wire(buf)?;
        if header.r#type != 2 {
            return Err(pktparser::ParseError::InvalidArgument(format!(
                "Want type 2 for PortID TLV but got {}",
                header.r#type,
            )));
        }

        let mut payload = buf
            .get_buffer(header.length.into())
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;

        let subtype = PortIDType::from_wire(&mut payload)?;

        let identifier: Vec<u8> = payload
            .get_vec(payload.remaining())
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;

        Ok(PortID {
            r#type: subtype,
            identifier,
        })
    }
}

impl ToWire for PortID {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        let mut value = Vec::new();
        value.append(&mut self.r#type.to_wire()?);
        value.append(&mut self.identifier.clone());

        let header = LLDPTLVHeader {
            r#type: 2,
            length: value.len() as u16,
        };
        let mut output = header.to_wire()?;
        output.append(&mut value);
        Ok(output)
    }
}

impl std::fmt::Display for PortID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // TODO: Actually treat the types correctly according to their value.
        write!(
            f,
            "PortID type: {} value: {:02x?}",
            self.r#type, self.identifier
        )
    }
}

#[derive(Debug)]
pub enum PortIDType {
    InterfaceAlias,
    PortComponent,
    MacAddress,
    NetworkAddress,
    InterfaceName,
    AgentCircuitID,
    Local,
}

impl FromWire for PortIDType {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        Ok(
            match buf
                .get_u8()
                .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?
            {
                1 => Self::InterfaceAlias,
                2 => Self::PortComponent,
                3 => Self::MacAddress,
                4 => Self::NetworkAddress,
                5 => Self::InterfaceName,
                6 => Self::AgentCircuitID,
                7 => Self::Local,
                other => {
                    return Err(pktparser::ParseError::InvalidArgument(format!(
                        "Unknown PortIDType: {}",
                        other
                    )))
                }
            },
        )
    }
}

impl ToWire for PortIDType {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        Ok(match self {
            Self::InterfaceAlias => vec![1],
            Self::PortComponent => vec![2],
            Self::MacAddress => vec![3],
            Self::NetworkAddress => vec![4],
            Self::InterfaceName => vec![5],
            Self::AgentCircuitID => vec![6],
            Self::Local => vec![7],
        })
    }
}

impl std::fmt::Display for PortIDType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InterfaceAlias => write!(f, "InterfaceAlias"),
            Self::PortComponent => write!(f, "PortComponent"),
            Self::MacAddress => write!(f, "MacAddress"),
            Self::NetworkAddress => write!(f, "NetworkAddress"),
            Self::InterfaceName => write!(f, "InterfaceName"),
            Self::AgentCircuitID => write!(f, "AgentCircuitID"),
            Self::Local => write!(f, "Local"),
        }
    }
}

#[derive(Debug)]
pub struct TTL {
    pub ttl: u16,
}

impl FromWire for TTL {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        let header = LLDPTLVHeader::from_wire(buf)?;
        if header.r#type != 3 {
            return Err(pktparser::ParseError::InvalidArgument(format!(
                "Want type 3 for TTL TLV but got {}",
                header.r#type,
            )));
        }
        if header.length != 2 {
            return Err(pktparser::ParseError::InvalidArgument(format!(
                "TTL TLV length must be 2 but got {}",
                header.length,
            )));
        }

        let ttl = buf
            .get_be16()
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;
        Ok(TTL { ttl })
    }
}

impl ToWire for TTL {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        let header = LLDPTLVHeader {
            r#type: 3,
            length: 2,
        };
        let mut output = header.to_wire()?;
        WriteBytesExt::write_u16::<BigEndian>(&mut output, self.ttl)?;
        Ok(output)
    }
}

impl std::fmt::Display for TTL {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "TTL: {} seconds", self.ttl)
    }
}

#[derive(Debug)]
pub struct PortDescription {
    pub description: String,
}

impl FromWire for PortDescription {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        let header = LLDPTLVHeader::from_wire(buf)?;
        if header.r#type != 4 {
            return Err(pktparser::ParseError::InvalidArgument(format!(
                "Want type 4 for PortDescription TLV but got {}",
                header.r#type,
            )));
        }

        let description: String = String::from_utf8(
            buf.get_vec(header.length.into())
                .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?,
        )
        .map_err(|e| pktparser::ParseError::InvalidArgument(e.to_string()))?;

        Ok(PortDescription { description })
    }
}

impl ToWire for PortDescription {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        let mut description_bytes = self.description.as_bytes().to_vec();
        let header = LLDPTLVHeader {
            r#type: 4,
            length: description_bytes.len() as u16,
        };

        let mut output = header.to_wire()?;
        output.append(&mut description_bytes);
        Ok(output)
    }
}

impl std::fmt::Display for PortDescription {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "PortDescription: {}", self.description)
    }
}

#[derive(Debug)]
pub struct SystemName {
    pub system_name: String,
}

impl FromWire for SystemName {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        let header = LLDPTLVHeader::from_wire(buf)?;
        if header.r#type != 5 {
            return Err(pktparser::ParseError::InvalidArgument(format!(
                "Want type 5 for SystemName TLV but got {}",
                header.r#type,
            )));
        }

        let system_name: String = String::from_utf8(
            buf.get_vec(header.length.into())
                .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?,
        )
        .map_err(|e| pktparser::ParseError::InvalidArgument(e.to_string()))?;

        Ok(SystemName { system_name })
    }
}

impl ToWire for SystemName {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        let mut system_name_bytes = self.system_name.as_bytes().to_vec();
        let header = LLDPTLVHeader {
            r#type: 5,
            length: system_name_bytes.len() as u16,
        };

        let mut output = header.to_wire()?;
        output.append(&mut system_name_bytes);
        Ok(output)
    }
}

impl std::fmt::Display for SystemName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "SystemName: {}", self.system_name)
    }
}

#[derive(Debug)]
pub struct SystemDescription {
    pub system_description: String,
}

impl FromWire for SystemDescription {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        let header = LLDPTLVHeader::from_wire(buf)?;
        if header.r#type != 6 {
            return Err(pktparser::ParseError::InvalidArgument(format!(
                "Want type 6 for SystemDescription TLV but got {}",
                header.r#type,
            )));
        }

        let system_description: String = String::from_utf8(
            buf.get_vec(header.length.into())
                .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?,
        )
        .map_err(|e| pktparser::ParseError::InvalidArgument(e.to_string()))?;

        Ok(SystemDescription { system_description })
    }
}

impl ToWire for SystemDescription {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        let mut system_description_bytes = self.system_description.as_bytes().to_vec();
        let header = LLDPTLVHeader {
            r#type: 6,
            length: system_description_bytes.len() as u16,
        };

        let mut output = header.to_wire()?;
        output.append(&mut system_description_bytes);
        Ok(output)
    }
}

impl std::fmt::Display for SystemDescription {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "SystemDescription: {}", self.system_description)
    }
}

#[derive(Debug)]
pub struct SystemCapabilities {
    pub sys_cap: u16,
    pub enabled_cap: u16,
}

impl FromWire for SystemCapabilities {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        let header = LLDPTLVHeader::from_wire(buf)?;
        if header.r#type != 7 {
            return Err(pktparser::ParseError::InvalidArgument(format!(
                "Want type 3 for SystemCapabilities TLV but got {}",
                header.r#type,
            )));
        }
        if header.length != 4 {
            return Err(pktparser::ParseError::InvalidArgument(format!(
                "SystemCapabilities TLV length must be 4 but got {}",
                header.length,
            )));
        }

        let sys_cap = buf
            .get_be16()
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;
        let enabled_cap = buf
            .get_be16()
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;

        Ok(SystemCapabilities {
            sys_cap,
            enabled_cap,
        })
    }
}

impl ToWire for SystemCapabilities {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        let header = LLDPTLVHeader {
            r#type: 7,
            length: 4,
        };
        let mut output = header.to_wire()?;
        WriteBytesExt::write_u16::<BigEndian>(&mut output, self.sys_cap)?;
        WriteBytesExt::write_u16::<BigEndian>(&mut output, self.enabled_cap)?;
        Ok(output)
    }
}

impl std::fmt::Display for SystemCapabilities {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(
            f,
            "SystemCapabilities system: {}, enabled: {}",
            self.sys_cap, self.enabled_cap
        )
    }
}

#[derive(Debug)]
pub struct ManagementAddress {
    pub address: Vec<u8>,
    /// Called management address subtype by IEEE802.1AB
    pub address_family: u8,
    pub numbering_subtype: u8,
    pub if_number: u32,
    pub oid: Vec<u8>,
}

impl FromWire for ManagementAddress {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        let header = LLDPTLVHeader::from_wire(buf)?;
        if header.r#type != 8 {
            return Err(pktparser::ParseError::InvalidArgument(format!(
                "Want type 8 for ManagementAddress TLV but got {}",
                header.r#type,
            )));
        }
        let mut payload = buf
            .get_buffer(header.length.into())
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;

        let mgmt_addr_len = payload
            .get_u8()
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)? as u8;
        let mgmt_addr_af = payload
            .get_u8()
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)? as u8;
        let mgmt_addr = payload
            .get_bytes(mgmt_addr_len.into())
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;

        let numbering_subtype: u8 = payload
            .get_u8()
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;
        let mut if_number_bytes = payload
            .get_bytes(4)
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;
        let if_number = ReadBytesExt::read_u32::<BigEndian>(&mut if_number_bytes).map_err(|e| {
            pktparser::ParseError::InvalidArgument(format!(
                "Failed to read if_number from ManagementAddr: {}",
                e.to_string()
            ))
        })?;

        let oid_len = payload
            .get_u8()
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;
        let oid = payload
            .get_bytes(oid_len.into())
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?
            .to_vec();

        Ok(ManagementAddress {
            address: mgmt_addr.to_vec(),
            address_family: mgmt_addr_af,
            numbering_subtype,
            if_number,
            oid,
        })
    }
}

impl ToWire for ManagementAddress {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        let mut payload: Vec<u8> = Vec::new();
        if self.address.len() > u8::MAX.into() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "management address too long: got {} but size is u8",
                    self.address.len()
                ),
            ));
        }
        payload.push(self.address.len() as u8);
        payload.push(self.address_family);
        payload.append(&mut self.address.clone());
        payload.push(self.numbering_subtype);
        WriteBytesExt::write_u32::<BigEndian>(&mut payload, self.if_number)?;
        if self.oid.len() > u8::MAX.into() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("oid too long: got {} but size is u8", self.oid.len()),
            ));
        }
        payload.push(self.oid.len() as u8);
        payload.append(&mut self.oid.clone());

        let header = LLDPTLVHeader {
            r#type: 8,
            length: payload.len() as u16,
        };
        let header_bytes = header.to_wire()?;
        payload.splice(0..0, header_bytes.iter().cloned());

        Ok(payload)
    }
}

impl std::fmt::Display for ManagementAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(
            f,
            "ManagementAddress address: {:02x?}, af: {}, numbering_subtype: {}, if_number: {}, oid: {:?}",
            self.address, self.address_family, self.numbering_subtype, self.if_number, self.oid
        )
    }
}

#[derive(Debug)]
pub struct OrganizationSpecific {
    pub oui: [u8; 3],
    pub subtype: u8,
    pub value: Vec<u8>,
}

impl FromWire for OrganizationSpecific {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        let header = LLDPTLVHeader::from_wire(buf)?;
        if header.r#type != 127 {
            return Err(pktparser::ParseError::InvalidArgument(format!(
                "Want type 127 for OrganizationSpecific TLV but got {}",
                header.r#type,
            )));
        }
        let mut payload = buf
            .get_buffer(header.length.into())
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;
        let oui = payload
            .get_bytes(3)
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?
            .to_vec();
        let subtype = payload
            .get_u8()
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;
        let value = payload
            .get_bytes((header.length - 4).into())
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;

        Ok(OrganizationSpecific {
            oui: oui
                .try_into()
                .expect("Error in converting Vec of len 3 to slice of len 3"),
            subtype,
            value: value.to_vec(),
        })
    }
}

impl ToWire for OrganizationSpecific {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        let mut payload = Vec::new();
        payload.append(&mut self.oui.to_vec());
        payload.push(self.subtype);
        payload.append(&mut self.value.clone());

        let header = LLDPTLVHeader {
            r#type: 127,
            length: payload.len() as u16,
        };
        let header_bytes = header.to_wire()?;
        payload.splice(0..0, header_bytes.iter().cloned());

        Ok(payload)
    }
}

impl std::fmt::Display for OrganizationSpecific {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(
            f,
            "OrganizationSpecific oui: {:02x?} subtype: {}, value: {:02x?}",
            self.oui, self.subtype, self.value
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_chassis_tlv() {
        let bytes = vec![0x02, 0x07, 0x04, 0x8c, 0x1f, 0x64, 0xac, 0xe0, 0x00];
        let parsed = ChassisID::from_wire(&mut pktparser::Buffer::new(&bytes)).unwrap();
        assert_eq!(
            "ChassisID type: MacAddress value: [8c, 1f, 64, ac, e0, 00]",
            parsed.to_string()
        );
        let reserialized = parsed.to_wire().unwrap();
        assert_eq!(reserialized, bytes);
    }

    #[test]
    fn parse_portid_tlv() {
        let bytes = vec![
            0x04, 0x0d, 0x01, 0x55, 0x70, 0x6c, 0x69, 0x6e, 0x6b, 0x20, 0x74, 0x6f, 0x20, 0x53,
            0x31,
        ];
        let parsed = PortID::from_wire(&mut pktparser::Buffer::new(&bytes)).unwrap();
        assert_eq!(
            "PortID type: InterfaceAlias value: [55, 70, 6c, 69, 6e, 6b, 20, 74, 6f, 20, 53, 31]",
            parsed.to_string()
        );
        let reserialized = parsed.to_wire().unwrap();
        assert_eq!(reserialized, bytes);
    }

    #[test]
    fn parse_ttl_tlv() {
        let bytes = vec![0x06, 0x02, 0x00, 0x78];
        let parsed = TTL::from_wire(&mut pktparser::Buffer::new(&bytes)).unwrap();
        assert_eq!("TTL: 120 seconds", parsed.to_string());
        let reserialized = parsed.to_wire().unwrap();
        assert_eq!(reserialized, bytes);
    }

    #[test]
    fn parse_system_name_tlv() {
        let bytes = vec![
            0x0a, 0x0c, 0x53, 0x32, 0x2e, 0x63, 0x69, 0x73, 0x63, 0x6f, 0x2e, 0x63, 0x6f, 0x6d,
        ];
        let parsed = SystemName::from_wire(&mut pktparser::Buffer::new(&bytes)).unwrap();
        assert_eq!("SystemName: S2.cisco.com", parsed.to_string());
        let reserialized = parsed.to_wire().unwrap();
        assert_eq!(reserialized, bytes);
    }

    #[test]
    fn parse_system_description_tlv() {
        let bytes = vec![
            0x0c, 0xbe, 0x43, 0x69, 0x73, 0x63, 0x6f, 0x20, 0x49, 0x4f, 0x53, 0x20, 0x53, 0x6f,
            0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x2c, 0x20, 0x43, 0x33, 0x35, 0x36, 0x30, 0x20,
            0x53, 0x6f, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x20, 0x28, 0x43, 0x33, 0x35, 0x36,
            0x30, 0x2d, 0x41, 0x44, 0x56, 0x49, 0x50, 0x53, 0x45, 0x52, 0x56, 0x49, 0x43, 0x45,
            0x53, 0x4b, 0x39, 0x2d, 0x4d, 0x29, 0x2c, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f,
            0x6e, 0x20, 0x31, 0x32, 0x2e, 0x32, 0x28, 0x34, 0x34, 0x29, 0x53, 0x45, 0x2c, 0x20,
            0x52, 0x45, 0x4c, 0x45, 0x41, 0x53, 0x45, 0x20, 0x53, 0x4f, 0x46, 0x54, 0x57, 0x41,
            0x52, 0x45, 0x20, 0x28, 0x66, 0x63, 0x31, 0x29, 0x0a, 0x43, 0x6f, 0x70, 0x79, 0x72,
            0x69, 0x67, 0x68, 0x74, 0x20, 0x28, 0x63, 0x29, 0x20, 0x31, 0x39, 0x38, 0x36, 0x2d,
            0x32, 0x30, 0x30, 0x38, 0x20, 0x62, 0x79, 0x20, 0x43, 0x69, 0x73, 0x63, 0x6f, 0x20,
            0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2c, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x0a,
            0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x64, 0x20, 0x53, 0x61, 0x74, 0x20, 0x30,
            0x35, 0x2d, 0x4a, 0x61, 0x6e, 0x2d, 0x30, 0x38, 0x20, 0x30, 0x30, 0x3a, 0x31, 0x35,
            0x20, 0x62, 0x79, 0x20, 0x77, 0x65, 0x69, 0x6c, 0x69, 0x75,
        ];
        let parsed = SystemDescription::from_wire(&mut pktparser::Buffer::new(&bytes)).unwrap();
        assert_eq!("SystemDescription: Cisco IOS Software, C3560 Software (C3560-ADVIPSERVICESK9-M), Version 12.2(44)SE, RELEASE SOFTWARE (fc1)\nCopyright (c) 1986-2008 by Cisco Systems, Inc.\nCompiled Sat 05-Jan-08 00:15 by weiliu", parsed.to_string());
        let reserialized = parsed.to_wire().unwrap();
        assert_eq!(reserialized, bytes);
    }

    #[test]
    fn parse_port_description_tlv() {
        let bytes = vec![
            0x08, 0x13, 0x47, 0x69, 0x67, 0x61, 0x62, 0x69, 0x74, 0x45, 0x74, 0x68, 0x65, 0x72,
            0x6e, 0x65, 0x74, 0x30, 0x2f, 0x31, 0x33,
        ];
        let parsed = PortDescription::from_wire(&mut pktparser::Buffer::new(&bytes)).unwrap();
        assert_eq!("PortDescription: GigabitEthernet0/13", parsed.to_string());
        let reserialized = parsed.to_wire().unwrap();
        assert_eq!(reserialized, bytes);
    }

    #[test]
    fn parse_capabilities_tlv() {
        let bytes = vec![0x0e, 0x04, 0x00, 0x14, 0x00, 0x04];
        let parsed = SystemCapabilities::from_wire(&mut pktparser::Buffer::new(&bytes)).unwrap();
        assert_eq!(
            "SystemCapabilities system: 20, enabled: 4",
            parsed.to_string()
        );
        let reserialized = parsed.to_wire().unwrap();
        assert_eq!(reserialized, bytes);
    }

    #[test]
    fn parse_organization_specific() {
        let bytes = vec![
            0xfe, 0x09, 0x00, 0x12, 0x0f, 0x01, 0x03, 0xc0, 0x36, 0x00, 0x10,
        ];
        let parsed = OrganizationSpecific::from_wire(&mut pktparser::Buffer::new(&bytes)).unwrap();
        assert_eq!(
            "OrganizationSpecific oui: [00, 12, 0f] subtype: 1, value: [03, c0, 36, 00, 10]",
            parsed.to_string()
        );
        let reserialized = parsed.to_wire().unwrap();
        assert_eq!(reserialized, bytes);
    }

    #[test]
    fn parse_lldp_packet() {
        let bytes = vec![
            0x02, 0x07, 0x04, 0x00, 0x19, 0x2f, 0xa7, 0xb2, 0x8d, 0x04, 0x0d, 0x01, 0x55, 0x70,
            0x6c, 0x69, 0x6e, 0x6b, 0x20, 0x74, 0x6f, 0x20, 0x53, 0x31, 0x06, 0x02, 0x00, 0x78,
            0x0a, 0x0c, 0x53, 0x32, 0x2e, 0x63, 0x69, 0x73, 0x63, 0x6f, 0x2e, 0x63, 0x6f, 0x6d,
            0x0c, 0xbe, 0x43, 0x69, 0x73, 0x63, 0x6f, 0x20, 0x49, 0x4f, 0x53, 0x20, 0x53, 0x6f,
            0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x2c, 0x20, 0x43, 0x33, 0x35, 0x36, 0x30, 0x20,
            0x53, 0x6f, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x20, 0x28, 0x43, 0x33, 0x35, 0x36,
            0x30, 0x2d, 0x41, 0x44, 0x56, 0x49, 0x50, 0x53, 0x45, 0x52, 0x56, 0x49, 0x43, 0x45,
            0x53, 0x4b, 0x39, 0x2d, 0x4d, 0x29, 0x2c, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f,
            0x6e, 0x20, 0x31, 0x32, 0x2e, 0x32, 0x28, 0x34, 0x34, 0x29, 0x53, 0x45, 0x2c, 0x20,
            0x52, 0x45, 0x4c, 0x45, 0x41, 0x53, 0x45, 0x20, 0x53, 0x4f, 0x46, 0x54, 0x57, 0x41,
            0x52, 0x45, 0x20, 0x28, 0x66, 0x63, 0x31, 0x29, 0x0a, 0x43, 0x6f, 0x70, 0x79, 0x72,
            0x69, 0x67, 0x68, 0x74, 0x20, 0x28, 0x63, 0x29, 0x20, 0x31, 0x39, 0x38, 0x36, 0x2d,
            0x32, 0x30, 0x30, 0x38, 0x20, 0x62, 0x79, 0x20, 0x43, 0x69, 0x73, 0x63, 0x6f, 0x20,
            0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2c, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x0a,
            0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x64, 0x20, 0x53, 0x61, 0x74, 0x20, 0x30,
            0x35, 0x2d, 0x4a, 0x61, 0x6e, 0x2d, 0x30, 0x38, 0x20, 0x30, 0x30, 0x3a, 0x31, 0x35,
            0x20, 0x62, 0x79, 0x20, 0x77, 0x65, 0x69, 0x6c, 0x69, 0x75, 0x08, 0x13, 0x47, 0x69,
            0x67, 0x61, 0x62, 0x69, 0x74, 0x45, 0x74, 0x68, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x30,
            0x2f, 0x31, 0x33, 0x0e, 0x04, 0x00, 0x14, 0x00, 0x04, 0xfe, 0x06, 0x00, 0x80, 0xc2,
            0x01, 0x00, 0x01, 0xfe, 0x09, 0x00, 0x12, 0x0f, 0x01, 0x03, 0xc0, 0x36, 0x00, 0x10,
            0x00, 0x00,
        ];
        let parsed = LLDPPacket::from_wire(&mut pktparser::Buffer::new(&bytes)).unwrap();
        assert_eq!("LLDP [\n\tChassisID type: MacAddress value: [00, 19, 2f, a7, b2, 8d]\n\tPortID type: InterfaceAlias value: [55, 70, 6c, 69, 6e, 6b, 20, 74, 6f, 20, 53, 31]\n\tTTL: 120 seconds\n\tSystemName: S2.cisco.com\n\tSystemDescription: Cisco IOS Software, C3560 Software (C3560-ADVIPSERVICESK9-M), Version 12.2(44)SE, RELEASE SOFTWARE (fc1)\nCopyright (c) 1986-2008 by Cisco Systems, Inc.\nCompiled Sat 05-Jan-08 00:15 by weiliu\n\tPortDescription: GigabitEthernet0/13\n\tSystemCapabilities system: 20, enabled: 4\n\tOrganizationSpecific oui: [00, 80, c2] subtype: 1, value: [00, 01]\n\tOrganizationSpecific oui: [00, 12, 0f] subtype: 1, value: [03, c0, 36, 00, 10]\n\tEnd of LLDPPDU\n]", parsed.to_string());
        let reserialized = parsed.to_wire().unwrap();
        assert_eq!(reserialized, bytes);
    }
}
