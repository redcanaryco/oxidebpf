use crate::xdp::constant::netlink::{NLA_ALIGNTO, NLMSG_ALIGNTO};
use std::os::raw::{c_int, c_uchar, c_uint, c_ushort};

pub(crate) mod constant;
pub(crate) mod syscall;

const fn align(v: usize, align: usize) -> usize {
    (v + (align - 1)) & !(align - 1)
}

const fn nlmsg_align(v: usize) -> usize {
    align(v, NLMSG_ALIGNTO as usize)
}

const fn nla_align(v: usize) -> usize {
    align(v, NLA_ALIGNTO as usize)
}

#[repr(C)]
struct NetlinkAttr {
    nla_len: c_ushort,
    nla_type: c_ushort,
}

#[repr(C)]
struct NetlinkRequest {
    nh: NetlinkMessageHeader,
    ifinfo: IfInfoMessage,
    attrbuf: [c_uchar; 64],
}

impl Default for NetlinkRequest {
    fn default() -> Self {
        Self {
            nh: libc::nlmsghdr {
                nlmsg_len: 0,
                nlmsg_type: 0,
                nlmsg_flags: 0,
                nlmsg_seq: 0,
                nlmsg_pid: 0,
            },
            ifinfo: IfInfoMessage::default(),
            attrbuf: [0u8; 64],
        }
    }
}

type NetlinkMessageHeader = libc::nlmsghdr;
type SockAddrNetlink = libc::sockaddr_nl;

#[repr(C)]
#[derive(Default)]
struct IfInfoMessage {
    ifi_family: c_uchar,
    __ifi_pad: c_uchar,
    ifi_type: c_ushort,
    ifi_index: c_int,
    ifi_flags: c_uint,
    ifi_change: c_uint,
}
