use crate::xdp::constant::ifla_xdp::IFLA_XDP_FD;
use crate::xdp::constant::netlink::{NLA_HDRLEN, NLMSG_HDRLEN};
use crate::xdp::constant::{XdpFlag, REQUEST_BUFFER_START};
use crate::xdp::{
    nla_align, nlmsg_align, IfInfoMessage, NetlinkAttr, NetlinkMessageHeader, NetlinkRequest,
    SockAddrNetlink,
};
use crate::OxidebpfError;
use nix::errno::{errno, Errno};
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::raw::{c_uint, c_ushort};
use std::os::unix::io::RawFd;
use std::slice;

fn bpf_set_link_xdp(fd: RawFd, interface_index: i32, _flags: u32) -> Result<(), OxidebpfError> {
    let mut req = NetlinkRequest {
        nh: NetlinkMessageHeader {
            nlmsg_len: (NLMSG_HDRLEN + std::mem::size_of::<IfInfoMessage>()) as c_uint,
            nlmsg_type: libc::RTM_SETLINK,
            nlmsg_flags: (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as c_ushort,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        },
        ifinfo: IfInfoMessage {
            ifi_family: libc::AF_UNSPEC as u8,
            __ifi_pad: 0,
            ifi_type: 0,
            ifi_index: interface_index,
            ifi_flags: 0,
            ifi_change: 0,
        },
        ..Default::default()
    };

    // create request, set attributes

    let nla_xdp = NetlinkAttr {
        nla_len: (NLA_HDRLEN + std::mem::size_of::<c_uint>()) as u16,
        nla_type: IFLA_XDP_FD as u16,
    };

    let nla = NetlinkAttr {
        nla_len: NLA_HDRLEN as u16 + nla_xdp.nla_len,
        nla_type: libc::IFLA_XDP | (libc::NLA_F_NESTED as u16),
    };

    let mut idx = 0;
    let nla_align_offset = nlmsg_align(req.nh.nlmsg_len as usize) - REQUEST_BUFFER_START;
    req.nh.nlmsg_len += nla_align(nla.nla_len as usize) as u32;
    let nla_slice = unsafe {
        slice::from_raw_parts(
            &nla as *const NetlinkAttr as *const u8,
            std::mem::size_of::<NetlinkAttr>(),
        )
    };
    for b in nla_slice.iter() {
        req.attrbuf[nla_align_offset + idx] = *b;
        idx += 1;
    }

    let nla_xdp_slice = unsafe {
        slice::from_raw_parts(
            &nla_xdp as *const NetlinkAttr as *const u8,
            std::mem::size_of::<NetlinkAttr>(),
        )
    };
    for b in nla_xdp_slice.iter() {
        req.attrbuf[nla_align_offset + idx] = *b;
        idx += 1;
    }
    let fd_bytes: [u8; 4] = unsafe { std::mem::transmute(fd) };
    for b in fd_bytes.iter() {
        req.attrbuf[nla_align_offset + idx] = *b;
        idx += 1;
    }

    // send it to the socket
    let socket = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    if socket < 0 {
        return Err(OxidebpfError::LinuxError(
            "Could not open netlink socket.".to_string(),
            nix::errno::from_i32(nix::errno::errno()),
        ));
    }

    let mut sa = unsafe { MaybeUninit::<SockAddrNetlink>::zeroed().assume_init() };
    sa.nl_family = libc::AF_NETLINK as u16;
    if unsafe {
        libc::bind(
            socket,
            &sa as *const SockAddrNetlink as *const libc::sockaddr,
            std::mem::size_of::<SockAddrNetlink>() as u32,
        )
    } < 0
    {
        return Err(OxidebpfError::LinuxError(
            "could not bind netlink socket".to_string(),
            nix::errno::from_i32(nix::errno::errno()),
        ));
    };

    let sent = unsafe {
        libc::send(
            socket,
            &req as *const NetlinkRequest as *const _,
            std::mem::size_of_val(&req) as libc::size_t,
            0,
        )
    };
    if sent < 0 {
        return Err(OxidebpfError::LinuxError(
            "could not send to netlink socket".to_string(),
            nix::errno::from_i32(nix::errno::errno()),
        ));
    }

    let mut buf = vec![0u8; 4096];
    // netlink recv
    let len = unsafe { libc::recv(socket, buf.as_mut_ptr() as *mut _, 4096, 0) };
    if len < 0 {
        return Err(OxidebpfError::LinuxError(
            "could not receive reply from netlink socket".to_string(),
            nix::errno::from_i32(nix::errno::errno()),
        ));
    }

    println!("{:02x?}", buf);

    // close the socket
    unsafe { libc::close(socket) };

    Ok(())
}

pub(crate) fn attach_xdp(
    fd: RawFd,
    attach_point: &str,
    flags: XdpFlag,
) -> Result<(), OxidebpfError> {
    #[allow(clippy::redundant_closure)] // it's not a function call
    let interface_name =
        CString::new(attach_point).map_err(|e| OxidebpfError::CStringConversionError(e))?;
    unsafe {
        let interface_index = libc::if_nametoindex(interface_name.as_ptr()) as i32;
        if interface_index == 0 {
            return Err(OxidebpfError::LinuxError(
                "could net get interface index".to_string(),
                Errno::from_i32(errno()),
            ));
        }
        bpf_set_link_xdp(fd, interface_index, flags as u32)
    }
}
