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

use std::convert::TryInto;

pub trait ToWire {
    fn to_wire(&self) -> Result<Vec<u8>, std::io::Error>;
}

pub trait FromWire {
    fn from_wire(buf: &mut pktparser::Buffer<'_>) -> Result<Self, pktparser::ParseError>
    where
        Self: Sized;
}

#[derive(Debug)]
pub struct LLDPPacket {
    pub version: u8,
    pub flags: u8,
    pub ttl: u16,
    pub tlvs: Vec<LLDPTLV>,
}

#[derive(Debug)]
pub struct LLDPTLVHeader {
    pub r#type: u8,  // 7 bits on the wire.
    pub length: u16, // 9 bits on the wire
}

impl ToWire for LLDPTLVHeader {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        let out: u16 = (0b1111_1110 & self.r#type) as u16 | 0b0000_0001_1111_1111 & self.length;
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
        let r#type = (input & 0b1111_1110_0000_0000) as u8;
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
}

impl ToWire for LLDPTLV {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        todo!()
    }
}

#[derive(Debug)]
pub struct ChassisID {
    r#type: ChassisIDType,
    string: String,
}

impl ToWire for ChassisID {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        let mut value: Vec<u8> = Vec::new();
        value.append(&mut self.r#type.to_wire()?);
        value.append(&mut self.string.as_bytes().to_vec());
        let header = LLDPTLVHeader {
            r#type: 1,
            length: 1 + self.string.len() as u16,
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

        let string: String = String::from_utf8(
            payload
                .get_vec(payload.size())
                .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?,
        )
        .map_err(|e| pktparser::ParseError::InvalidArgument(e.to_string()))?;

        Ok(ChassisID {
            r#type: subtype,
            string,
        })
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

#[derive(Debug)]
pub struct PortID {
    pub r#type: PortIDType,
    pub string: String,
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

        let string: String = String::from_utf8(
            payload
                .get_vec(payload.size())
                .ok_or(pktparser::ParseError::UnexpectedEndOfInput)?,
        )
        .map_err(|e| pktparser::ParseError::InvalidArgument(e.to_string()))?;

        Ok(PortID {
            r#type: subtype,
            string,
        })
    }
}

impl ToWire for PortID {
    fn to_wire(&self) -> std::result::Result<Vec<u8>, std::io::Error> {
        let mut value = Vec::new();
        value.append(&mut self.r#type.to_wire()?);
        value.append(&mut self.string.as_bytes().to_vec());

        let header = LLDPTLVHeader {
            r#type: 2,
            length: value.len() as u16,
        };
        let mut output = header.to_wire()?;
        output.append(&mut value);
        Ok(output)
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
