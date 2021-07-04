use crate::xdp::constant::netlink::NLMSG_HDRLEN;
use crate::xdp::constant::XdpFlag::{
    XDP_FLAGS_DRV_MODE, XDP_FLAGS_HW_MODE, XDP_FLAGS_MODES, XDP_FLAGS_REPLACE, XDP_FLAGS_SKB_MODE,
    XDP_FLAGS_UPDATE_IF_NOEXIST,
};
use crate::xdp::IfInfoMessage;

pub(crate) const REQUEST_BUFFER_START: usize = NLMSG_HDRLEN + std::mem::size_of::<IfInfoMessage>();

pub(crate) mod netlink {
    use crate::xdp::{nla_align, nlmsg_align, NetlinkAttr};

    pub(crate) const NLMSG_ALIGNTO: u32 = 4;
    pub(crate) const NLMSG_HDRLEN: usize = nlmsg_align(std::mem::size_of::<libc::nlmsghdr>());
    pub(crate) const NLA_ALIGNTO: u32 = 4;
    pub(crate) const NLA_HDRLEN: usize = nla_align(std::mem::size_of::<NetlinkAttr>());
}

pub(crate) mod ifla_xdp {
    pub(crate) const IFLA_XDP_UNSPEC: usize = 0;
    pub(crate) const IFLA_XDP_FD: usize = 1;
    pub(crate) const IFLA_XDP_ATTACHED: usize = 2;
    pub(crate) const IFLA_XDP_FLAGS: usize = 3;
    pub(crate) const IFLA_XDP_PROG_ID: usize = 4;
    pub(crate) const IFLA_XDP_DRV_PROG_ID: usize = 5;
    pub(crate) const IFLA_XDP_SKB_PROG_ID: usize = 6;
    pub(crate) const IFLA_XDP_HW_PROG_ID: usize = 7;
    pub(crate) const IFLA_XDP_EXPECTED_FD: usize = 8;
    pub(crate) const __IFLA_XDP_MAX: usize = 9;
}

#[allow(non_camel_case_types)]
pub(crate) enum XdpFlag {
    Unset = 0,
    XDP_FLAGS_UPDATE_IF_NOEXIST = (1 << 0),
    XDP_FLAGS_SKB_MODE = (1 << 1),
    XDP_FLAGS_DRV_MODE = (1 << 2),
    XDP_FLAGS_HW_MODE = (1 << 3),
    XDP_FLAGS_REPLACE = (1 << 4),
    XDP_FLAGS_MODES = (XDP_FLAGS_SKB_MODE as isize)
        | (XDP_FLAGS_DRV_MODE as isize)
        | (XDP_FLAGS_HW_MODE as isize),
    XDP_FLAGS_MASK = (XDP_FLAGS_UPDATE_IF_NOEXIST as isize)
        | (XDP_FLAGS_MODES as isize)
        | (XDP_FLAGS_REPLACE as isize),
}
