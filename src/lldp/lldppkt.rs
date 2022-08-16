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
use pktparser::{Deserialise, Serialise};

use std::convert::TryInto;
use std::fmt::Formatter;
use std::io::ErrorKind;

/// LldpPacket represents a LLDP PDU that can be read from / written to the wire.
/// LLDP PDUs are simply a concatenation of TLVs in an Ethernet frame with type 0x88cc.
/// At the end of the PDU there is an empty TLV header.
/// The first three TLVs must be: ChassisID, PortID and TTL.
#[derive(Debug)]
pub struct LldpPacket {
    pub tlvs: Vec<LldpTlv>,
}

impl LldpPacket {
    fn validate_format(&self) -> Result<(), std::io::Error> {
        if self.tlvs.len() < 4 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "At least 4 mandatory TLVs are required in an LLDP PDU.",
            ));
        }

        // Safe to unwrap four elements since we checked above.
        let first: &LldpTlv = self.tlvs.get(0).unwrap();
        let second: &LldpTlv = self.tlvs.get(1).unwrap();
        let third: &LldpTlv = self.tlvs.get(2).unwrap();
        let last: &LldpTlv = self.tlvs.get(self.tlvs.len() - 1).unwrap();

        if !matches!(first, LldpTlv::ChassisID(_)) {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("Expected first TLV to be ChassisID but got {}", first),
            ));
        }
        if !matches!(second, LldpTlv::PortID(_)) {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("Expected second TLV to be PortID but got {}", second),
            ));
        }
        if !matches!(third, LldpTlv::TTL(_)) {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("Expected third TLV to be TTL but got {}", third),
            ));
        }
        if !matches!(last, LldpTlv::EndOfLLDPPDU()) {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("Expected last TLV to be EndOfLLDPPDU but got {}", last),
            ));
        }

        Ok(())
    }
}

impl Serialise for LldpPacket {
    fn to_wire(&self) -> Result<Vec<u8>, std::io::Error> {
        self.validate_format()?;
        let mut pdu = Vec::new();

        for tlv in &self.tlvs {
            pdu.append(&mut tlv.to_wire()?);
        }

        Ok(pdu)
    }
}

impl Deserialise for LldpPacket {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        let mut tlvs = Vec::new();
        while buf.remaining() > 0 {
            tlvs.push(LldpTlv::from_wire(buf)?);
            if matches!(tlvs[tlvs.len() - 1], LldpTlv::EndOfLLDPPDU()) {
                return Ok(LldpPacket { tlvs });
            }
        }
        Err(pktparser::ParseError::InvalidArgument(
            "Malformed LLDP packet: missing End of LLDP PDU TLV".to_string(),
        ))
    }
}

impl std::fmt::Display for LldpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "LLDP [\n")?;
        for tlv in &self.tlvs {
            write!(f, "\t{}\n", tlv)?;
        }
        write!(f, "]")
    }
}

#[derive(Debug)]
pub struct LldpTlvHeader {
    pub ty: u8,      // 7 bits on the wire.
    pub length: u16, // 9 bits on the wire
}

impl Serialise for LldpTlvHeader {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        let out: u16 = ((self.ty as u16) << 9) as u16 | (0b0000_0001_1111_1111 & self.length);
        let mut vec = vec![];
        WriteBytesExt::write_u16::<BigEndian>(&mut vec, out)?;
        Ok(vec)
    }
}

impl Deserialise for LldpTlvHeader {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        let input = buf
            .get_be16()
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;
        let r#type = ((input & 0b1111_1110_0000_0000) >> 9) as u8;
        let length = input & 0b0000_0001_1111_1111;

        Ok(LldpTlvHeader { ty: r#type, length })
    }
}

#[derive(Debug)]
pub enum LldpTlv {
    /// 8.5.2
    ChassisID(ChassisId),
    /// 8.5.3
    PortID(PortId),
    /// 8.5.4
    TTL(Ttl),
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
    /// 8.6
    OrganizationSpecific(OrganizationSpecific),

    // A type to hold stuff we don't know, properly.
    UnknownTLV(UnknownTlv),

    EndOfLLDPPDU(),
}

impl Serialise for LldpTlv {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        let mut tlv_hdr = LldpTlvHeader { ty: 0, length: 0 };
        let mut payload: Vec<u8>;
        match self {
            Self::ChassisID(tlv) => {
                tlv_hdr.ty = 1;
                payload = tlv.to_wire()?;
            }
            Self::PortID(tlv) => {
                tlv_hdr.ty = 2;
                payload = tlv.to_wire()?;
            }
            Self::TTL(tlv) => {
                tlv_hdr.ty = 3;
                payload = tlv.to_wire()?;
            }
            Self::PortDescription(tlv) => {
                tlv_hdr.ty = 4;
                payload = tlv.to_wire()?;
            }
            Self::SystemName(tlv) => {
                tlv_hdr.ty = 5;
                payload = tlv.to_wire()?;
            }
            Self::SystemDescription(tlv) => {
                tlv_hdr.ty = 6;
                payload = tlv.to_wire()?;
            }
            Self::SystemCapabilities(tlv) => {
                tlv_hdr.ty = 7;
                payload = tlv.to_wire()?;
            }
            Self::ManagementAddress(tlv) => {
                tlv_hdr.ty = 8;
                payload = tlv.to_wire()?;
            }
            Self::OrganizationSpecific(tlv) => {
                tlv_hdr.ty = 127;
                payload = tlv.to_wire()?;
            }
            Self::UnknownTLV(tlv) => {
                tlv_hdr.ty = tlv.ty;
                payload = tlv.payload.clone();
            }
            Self::EndOfLLDPPDU() => {
                tlv_hdr.ty = 0;
                payload = vec![];
            }
        };
        tlv_hdr.length = payload.len() as u16;
        let mut result = tlv_hdr.to_wire()?;
        result.append(&mut payload);
        Ok(result)
    }
}

impl Deserialise for LldpTlv {
    fn from_wire(buf: &mut pktparser::Buffer<'_>) -> Result<Self, pktparser::ParseError>
    where
        Self: Sized,
    {
        let ty = ((buf
            .get_u8()
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?)
            & 0b1111_1110)
            >> 1;
        let len = buf
            .get_u8()
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;
        let mut payload = buf
            .get_buffer(len.into())
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;

        match ty {
            0 => Ok(Self::EndOfLLDPPDU()),
            1 => Ok(LldpTlv::ChassisID(ChassisId::from_wire(&mut payload)?)),
            2 => Ok(LldpTlv::PortID(PortId::from_wire(&mut payload)?)),
            3 => Ok(LldpTlv::TTL(Ttl::from_wire(&mut payload)?)),
            4 => Ok(LldpTlv::PortDescription(PortDescription::from_wire(
                &mut payload,
            )?)),
            5 => Ok(LldpTlv::SystemName(SystemName::from_wire(&mut payload)?)),
            6 => Ok(LldpTlv::SystemDescription(SystemDescription::from_wire(
                &mut payload,
            )?)),
            7 => Ok(LldpTlv::SystemCapabilities(SystemCapabilities::from_wire(
                &mut payload,
            )?)),
            8 => Ok(LldpTlv::ManagementAddress(ManagementAddress::from_wire(
                &mut payload,
            )?)),
            127 => Ok(LldpTlv::OrganizationSpecific(
                OrganizationSpecific::from_wire(&mut payload)?,
            )),
            _ => {
                let payload_vec = payload
                    .get_vec(payload.remaining())
                    .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;
                Ok(LldpTlv::UnknownTLV(UnknownTlv {
                    ty,
                    payload: payload_vec,
                }))
            }
        }
    }
}

impl std::fmt::Display for LldpTlv {
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
            Self::UnknownTLV(tlv) => tlv.fmt(f),
            Self::EndOfLLDPPDU() => write!(f, "End of LLDPPDU"),
        }
    }
}

#[derive(Debug)]
pub struct UnknownTlv {
    ty: u8,
    payload: Vec<u8>,
}

impl Serialise for UnknownTlv {
    fn to_wire(&self) -> Result<Vec<u8>, std::io::Error> {
        let header = LldpTlvHeader {
            ty: self.ty,
            length: self.payload.len() as u16,
        };

        let mut res = header.to_wire()?;
        res.append(&mut self.payload.clone());
        Ok(res)
    }
}

impl std::fmt::Display for UnknownTlv {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Unknown TLV type: {}, payload: {:02x?}",
            self.ty, self.payload
        )
    }
}

#[derive(Debug)]
pub struct ChassisId {
    r#type: ChassisIdType,
    identifier: Vec<u8>,
}

impl Serialise for ChassisId {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        let mut result: Vec<u8> = Vec::new();
        result.append(&mut self.r#type.to_wire()?);
        result.append(&mut self.identifier.clone());
        Ok(result)
    }
}

impl Deserialise for ChassisId {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        let subtype = ChassisIdType::from_wire(buf)?;

        let identifier: Vec<u8> = buf
            .get_vec(buf.remaining())
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;

        Ok(ChassisId {
            r#type: subtype,
            identifier,
        })
    }
}

impl std::fmt::Display for ChassisId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ChassisID type: {} value: {:02x?}",
            self.r#type, self.identifier
        )
    }
}

#[derive(Debug)]
pub enum ChassisIdType {
    ChassisComponent,
    InterfaceAlias,
    PortComponent,
    MacAddress,
    NetworkAddress,
    InterfaceName,
    Local,
}

impl Deserialise for ChassisIdType {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<ChassisIdType, pktparser::ParseError> {
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

impl Serialise for ChassisIdType {
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

impl std::fmt::Display for ChassisIdType {
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
pub struct PortId {
    pub r#type: PortIdType,
    pub identifier: Vec<u8>,
}

impl Deserialise for PortId {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        let subtype = PortIdType::from_wire(buf)?;

        let identifier: Vec<u8> = buf
            .get_vec(buf.remaining())
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;

        Ok(PortId {
            r#type: subtype,
            identifier,
        })
    }
}

impl Serialise for PortId {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        let mut result = Vec::new();
        result.append(&mut self.r#type.to_wire()?);
        result.append(&mut self.identifier.clone());
        Ok(result)
    }
}

impl std::fmt::Display for PortId {
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
pub enum PortIdType {
    InterfaceAlias,
    PortComponent,
    MacAddress,
    NetworkAddress,
    InterfaceName,
    AgentCircuitID,
    Local,
}

impl Deserialise for PortIdType {
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

impl Serialise for PortIdType {
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

impl std::fmt::Display for PortIdType {
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
pub struct Ttl(u16);

impl Deserialise for Ttl {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        if buf.remaining() != 2 {
            return Err(pktparser::ParseError::InvalidArgument(format!(
                "TTL TLV length must be 2 but got {}",
                buf.remaining(),
            )));
        }

        let ttl = buf
            .get_be16()
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;
        Ok(Ttl(ttl))
    }
}

impl Serialise for Ttl {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        let mut result = Vec::new();
        WriteBytesExt::write_u16::<BigEndian>(&mut result, self.0)?;
        Ok(result)
    }
}

impl std::fmt::Display for Ttl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "TTL: {} seconds", self.0)
    }
}

#[derive(Debug)]
pub struct PortDescription {
    pub description: String,
}

impl Deserialise for PortDescription {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        let description: String = String::from_utf8(
            buf.get_vec(buf.remaining())
                .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?,
        )
        .map_err(|e| pktparser::ParseError::InvalidArgument(e.to_string()))?;

        Ok(PortDescription { description })
    }
}

impl Serialise for PortDescription {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        Ok(self.description.as_bytes().to_vec())
    }
}

impl std::fmt::Display for PortDescription {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "PortDescription: {}", self.description)
    }
}

#[derive(Debug)]
pub struct SystemName(String);

impl Deserialise for SystemName {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        let system_name: String = String::from_utf8(
            buf.get_vec(buf.remaining())
                .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?,
        )
        .map_err(|e| pktparser::ParseError::InvalidArgument(e.to_string()))?;

        Ok(SystemName(system_name))
    }
}

impl Serialise for SystemName {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        Ok(self.0.as_bytes().to_vec())
    }
}

impl std::fmt::Display for SystemName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "SystemName: {}", self.0)
    }
}

#[derive(Debug)]
pub struct SystemDescription(String);

impl Deserialise for SystemDescription {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        let system_description: String = String::from_utf8(
            buf.get_vec(buf.remaining())
                .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?,
        )
        .map_err(|e| pktparser::ParseError::InvalidArgument(e.to_string()))?;

        Ok(SystemDescription(system_description))
    }
}

impl Serialise for SystemDescription {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        Ok(self.0.as_bytes().to_vec())
    }
}

impl std::fmt::Display for SystemDescription {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "SystemDescription: {}", self.0)
    }
}

#[derive(Debug)]
pub struct SystemCapabilities {
    pub sys_cap: u16,
    pub enabled_cap: u16,
}

impl Deserialise for SystemCapabilities {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        if buf.remaining() != 4 {
            return Err(pktparser::ParseError::InvalidArgument(format!(
                "SystemCapabilities TLV length must be 4 but got {}",
                buf.remaining(),
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

impl Serialise for SystemCapabilities {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        let mut result = Vec::new();
        WriteBytesExt::write_u16::<BigEndian>(&mut result, self.sys_cap)?;
        WriteBytesExt::write_u16::<BigEndian>(&mut result, self.enabled_cap)?;
        Ok(result)
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

impl Deserialise for ManagementAddress {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        let mgmt_addr_len = buf
            .get_u8()
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)? as u8;
        let mgmt_addr_af = buf
            .get_u8()
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)? as u8;
        let mgmt_addr = buf
            .get_bytes(mgmt_addr_len.into())
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;

        let numbering_subtype: u8 = buf
            .get_u8()
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;
        let mut if_number_bytes = buf
            .get_bytes(4)
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;
        let if_number = ReadBytesExt::read_u32::<BigEndian>(&mut if_number_bytes).map_err(|e| {
            pktparser::ParseError::InvalidArgument(format!(
                "Failed to read if_number from ManagementAddr: {}",
                e.to_string()
            ))
        })?;

        let oid_len = buf
            .get_u8()
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;
        let oid = buf
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

impl Serialise for ManagementAddress {
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

impl Deserialise for OrganizationSpecific {
    fn from_wire(
        buf: &mut pktparser::Buffer<'_>,
    ) -> std::result::Result<Self, pktparser::ParseError> {
        let oui = buf
            .get_bytes(3)
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?
            .to_vec();
        let subtype = buf
            .get_u8()
            .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?;
        let value = buf
            .get_bytes(buf.remaining())
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

impl Serialise for OrganizationSpecific {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        let mut payload = Vec::new();
        payload.append(&mut self.oui.to_vec());
        payload.push(self.subtype);
        payload.append(&mut self.value.clone());
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
        let parsed = LldpTlv::from_wire(&mut pktparser::Buffer::new(&bytes)).unwrap();
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
        let parsed = LldpTlv::from_wire(&mut pktparser::Buffer::new(&bytes)).unwrap();
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
        let parsed = LldpTlv::from_wire(&mut pktparser::Buffer::new(&bytes)).unwrap();
        assert_eq!("TTL: 120 seconds", parsed.to_string());
        let reserialized = parsed.to_wire().unwrap();
        assert_eq!(reserialized, bytes);
    }

    #[test]
    fn parse_system_name_tlv() {
        let bytes = vec![
            0x0a, 0x0c, 0x53, 0x32, 0x2e, 0x63, 0x69, 0x73, 0x63, 0x6f, 0x2e, 0x63, 0x6f, 0x6d,
        ];
        let parsed = LldpTlv::from_wire(&mut pktparser::Buffer::new(&bytes)).unwrap();
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
        let parsed = LldpTlv::from_wire(&mut pktparser::Buffer::new(&bytes)).unwrap();
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
        let parsed = LldpTlv::from_wire(&mut pktparser::Buffer::new(&bytes)).unwrap();
        assert_eq!("PortDescription: GigabitEthernet0/13", parsed.to_string());
        let reserialized = parsed.to_wire().unwrap();
        assert_eq!(reserialized, bytes);
    }

    #[test]
    fn parse_capabilities_tlv() {
        let bytes = vec![0x0e, 0x04, 0x00, 0x14, 0x00, 0x04];
        let parsed = LldpTlv::from_wire(&mut pktparser::Buffer::new(&bytes)).unwrap();
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
        let parsed = LldpTlv::from_wire(&mut pktparser::Buffer::new(&bytes)).unwrap();
        assert_eq!(
            "OrganizationSpecific oui: [00, 12, 0f] subtype: 1, value: [03, c0, 36, 00, 10]",
            parsed.to_string()
        );
        let reserialized = parsed.to_wire().unwrap();
        assert_eq!(reserialized, bytes);
    }

    #[test]
    fn parse_unknown_tlv() {
        let bytes = vec![0xaa, 0x01, 0x42];
        let parsed = LldpTlv::from_wire(&mut pktparser::Buffer::new(&bytes)).unwrap();
        assert_eq!("Unknown TLV type: 85, payload: [42]", parsed.to_string());
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
        let parsed = LldpPacket::from_wire(&mut pktparser::Buffer::new(&bytes)).unwrap();
        assert_eq!("LLDP [\n\tChassisID type: MacAddress value: [00, 19, 2f, a7, b2, 8d]\n\tPortID type: InterfaceAlias value: [55, 70, 6c, 69, 6e, 6b, 20, 74, 6f, 20, 53, 31]\n\tTTL: 120 seconds\n\tSystemName: S2.cisco.com\n\tSystemDescription: Cisco IOS Software, C3560 Software (C3560-ADVIPSERVICESK9-M), Version 12.2(44)SE, RELEASE SOFTWARE (fc1)\nCopyright (c) 1986-2008 by Cisco Systems, Inc.\nCompiled Sat 05-Jan-08 00:15 by weiliu\n\tPortDescription: GigabitEthernet0/13\n\tSystemCapabilities system: 20, enabled: 4\n\tOrganizationSpecific oui: [00, 80, c2] subtype: 1, value: [00, 01]\n\tOrganizationSpecific oui: [00, 12, 0f] subtype: 1, value: [03, c0, 36, 00, 10]\n\tEnd of LLDPPDU\n]", parsed.to_string());
        let reserialized = parsed.to_wire().unwrap();
        assert_eq!(reserialized, bytes);
    }
}
