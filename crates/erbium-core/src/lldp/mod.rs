use crate::lldp::lldppkt::*;

use erbium_net::raw::MsgFlags;

pub mod lldppkt;

pub struct LldpService {
    sock: erbium_net::raw::RawSocket,
}

impl LldpService {
    pub fn new() -> std::io::Result<LldpService> {
        let sock = erbium_net::raw::RawSocket::new(erbium_net::raw::EthProto::LLDP)?;
        Ok(Self { sock })
    }

    pub async fn run(&self) -> ! {
        let mut prev = None;
        loop {
            match self.sock.recv_msg(1500, MsgFlags::empty()).await {
                Err(err) => log::warn!("LLDP Failed to receive frame: {:?}", err),
                Ok(msg) => {
                    use crate::pktparser::Deserialise as _;
                    match lldppkt::LldpPacket::from_wire(&mut crate::pktparser::Buffer::new(
                        &msg.buffer[14..],
                    )) {
                        Ok(new) => {
                            if prev.is_none() || prev.as_ref().unwrap() != &new {
                                for i in &new.tlvs {
                                    match i {
                                        LldpTlv::ChassisID(ChassisId {
                                            r#type: ChassisIdType::ChassisComponent,
                                            identifier,
                                        }) => log::info!(
                                            "{:?}: Peer Chassis Component: {:?}",
                                            msg.local_intf(),
                                            identifier
                                        ),
                                        LldpTlv::ChassisID(ChassisId {
                                            r#type: ChassisIdType::InterfaceAlias,
                                            identifier,
                                        }) => log::info!(
                                            "{:?}: Peer IfAlias: {}",
                                            msg.local_intf(),
                                            String::from_utf8_lossy(&identifier)
                                        ),
                                        LldpTlv::ChassisID(ChassisId {
                                            r#type: ChassisIdType::PortComponent,
                                            identifier,
                                        }) => log::info!(
                                            "{:?}: Peer entPhysicalAlias: {}",
                                            msg.local_intf(),
                                            String::from_utf8_lossy(&identifier)
                                        ),
                                        LldpTlv::ChassisID(ChassisId {
                                            r#type: ChassisIdType::MacAddress,
                                            identifier,
                                        }) => log::info!(
                                            "{:?}: Peer Device MAC Address: {:?}",
                                            msg.local_intf(),
                                            identifier
                                                .iter()
                                                .map(|o| format!("{:0>2x}", o))
                                                .collect::<Vec<_>>()
                                                .join(":")
                                        ),
                                        LldpTlv::ChassisID(ChassisId {
                                            r#type: ChassisIdType::NetworkAddress,
                                            identifier,
                                        }) => log::info!(
                                            "{:?}: Peer Device Network Address: {:?}",
                                            msg.local_intf(),
                                            /* TODO: Render this as an IPv4/IPv6 address */
                                            identifier
                                                .iter()
                                                .map(|o| format!("{:0>2x}", o))
                                                .collect::<Vec<_>>()
                                                .join(":")
                                        ),
                                        LldpTlv::ChassisID(ChassisId {
                                            r#type: ChassisIdType::InterfaceName,
                                            identifier,
                                        }) => log::info!(
                                            "{:?}: Peer Interface Name: {}",
                                            msg.local_intf(),
                                            String::from_utf8_lossy(identifier)
                                        ),
                                        LldpTlv::ChassisID(ChassisId {
                                            r#type: ChassisIdType::Local,
                                            identifier,
                                        }) => log::info!(
                                            "{:?}: Peer Locally Defined Name: {}",
                                            msg.local_intf(),
                                            String::from_utf8_lossy(&identifier)
                                        ),
                                        LldpTlv::PortID(PortId {
                                            r#type: ty,
                                            identifier,
                                        }) => {
                                            log::info!(
                                                "{:?}: Peer Port {:?}: {}",
                                                msg.local_intf(),
                                                ty,
                                                String::from_utf8_lossy(&identifier)
                                            );
                                        }
                                        other => {
                                            log::info!(
                                                "{:?}: Peer Attribute: {:?}",
                                                msg.local_intf(),
                                                other
                                            );
                                        }
                                    }
                                }
                                prev = Some(new);
                            }
                        }
                        Err(e) => log::warn!("Failed to decode LLDP frame: {:?}", e),
                    }
                }
            }
        }
    }
}
