/* automatically generated by rust-bindgen */

#[repr(C)]
#[derive(Default)]
pub struct __IncompleteArrayField<T>(::std::marker::PhantomData<T>);
impl <T> __IncompleteArrayField<T> {
    #[inline]
    pub fn new() -> Self {
        __IncompleteArrayField(::std::marker::PhantomData)
    }
    #[inline]
    pub unsafe fn as_ptr(&self) -> *const T { ::std::mem::transmute(self) }
    #[inline]
    pub unsafe fn as_mut_ptr(&mut self) -> *mut T {
        ::std::mem::transmute(self)
    }
    #[inline]
    pub unsafe fn as_slice(&self, len: usize) -> &[T] {
        ::std::slice::from_raw_parts(self.as_ptr(), len)
    }
    #[inline]
    pub unsafe fn as_mut_slice(&mut self, len: usize) -> &mut [T] {
        ::std::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }
}
impl <T> ::std::fmt::Debug for __IncompleteArrayField<T> {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        fmt.write_str("__IncompleteArrayField")
    }
}
impl <T> ::std::clone::Clone for __IncompleteArrayField<T> {
    #[inline]
    fn clone(&self) -> Self { Self::new() }
}
impl <T> ::std::marker::Copy for __IncompleteArrayField<T> { }
pub const __BITS_PER_LONG: ::std::os::raw::c_uint = 64;
pub const __FD_SETSIZE: ::std::os::raw::c_uint = 1024;
pub const ETH_ALEN: ::std::os::raw::c_uint = 6;
pub const ETH_HLEN: ::std::os::raw::c_uint = 14;
pub const ETH_ZLEN: ::std::os::raw::c_uint = 60;
pub const ETH_DATA_LEN: ::std::os::raw::c_uint = 1500;
pub const ETH_FRAME_LEN: ::std::os::raw::c_uint = 1514;
pub const ETH_FCS_LEN: ::std::os::raw::c_uint = 4;
pub const ETH_P_LOOP: ::std::os::raw::c_uint = 96;
pub const ETH_P_PUP: ::std::os::raw::c_uint = 512;
pub const ETH_P_PUPAT: ::std::os::raw::c_uint = 513;
pub const ETH_P_TSN: ::std::os::raw::c_uint = 8944;
pub const ETH_P_IP: ::std::os::raw::c_uint = 2048;
pub const ETH_P_X25: ::std::os::raw::c_uint = 2053;
pub const ETH_P_ARP: ::std::os::raw::c_uint = 2054;
pub const ETH_P_BPQ: ::std::os::raw::c_uint = 2303;
pub const ETH_P_IEEEPUP: ::std::os::raw::c_uint = 2560;
pub const ETH_P_IEEEPUPAT: ::std::os::raw::c_uint = 2561;
pub const ETH_P_BATMAN: ::std::os::raw::c_uint = 17157;
pub const ETH_P_DEC: ::std::os::raw::c_uint = 24576;
pub const ETH_P_DNA_DL: ::std::os::raw::c_uint = 24577;
pub const ETH_P_DNA_RC: ::std::os::raw::c_uint = 24578;
pub const ETH_P_DNA_RT: ::std::os::raw::c_uint = 24579;
pub const ETH_P_LAT: ::std::os::raw::c_uint = 24580;
pub const ETH_P_DIAG: ::std::os::raw::c_uint = 24581;
pub const ETH_P_CUST: ::std::os::raw::c_uint = 24582;
pub const ETH_P_SCA: ::std::os::raw::c_uint = 24583;
pub const ETH_P_TEB: ::std::os::raw::c_uint = 25944;
pub const ETH_P_RARP: ::std::os::raw::c_uint = 32821;
pub const ETH_P_ATALK: ::std::os::raw::c_uint = 32923;
pub const ETH_P_AARP: ::std::os::raw::c_uint = 33011;
pub const ETH_P_8021Q: ::std::os::raw::c_uint = 33024;
pub const ETH_P_IPX: ::std::os::raw::c_uint = 33079;
pub const ETH_P_IPV6: ::std::os::raw::c_uint = 34525;
pub const ETH_P_PAUSE: ::std::os::raw::c_uint = 34824;
pub const ETH_P_SLOW: ::std::os::raw::c_uint = 34825;
pub const ETH_P_WCCP: ::std::os::raw::c_uint = 34878;
pub const ETH_P_MPLS_UC: ::std::os::raw::c_uint = 34887;
pub const ETH_P_MPLS_MC: ::std::os::raw::c_uint = 34888;
pub const ETH_P_ATMMPOA: ::std::os::raw::c_uint = 34892;
pub const ETH_P_PPP_DISC: ::std::os::raw::c_uint = 34915;
pub const ETH_P_PPP_SES: ::std::os::raw::c_uint = 34916;
pub const ETH_P_LINK_CTL: ::std::os::raw::c_uint = 34924;
pub const ETH_P_ATMFATE: ::std::os::raw::c_uint = 34948;
pub const ETH_P_PAE: ::std::os::raw::c_uint = 34958;
pub const ETH_P_AOE: ::std::os::raw::c_uint = 34978;
pub const ETH_P_8021AD: ::std::os::raw::c_uint = 34984;
pub const ETH_P_802_EX1: ::std::os::raw::c_uint = 34997;
pub const ETH_P_TIPC: ::std::os::raw::c_uint = 35018;
pub const ETH_P_8021AH: ::std::os::raw::c_uint = 35047;
pub const ETH_P_MVRP: ::std::os::raw::c_uint = 35061;
pub const ETH_P_1588: ::std::os::raw::c_uint = 35063;
pub const ETH_P_PRP: ::std::os::raw::c_uint = 35067;
pub const ETH_P_FCOE: ::std::os::raw::c_uint = 35078;
pub const ETH_P_TDLS: ::std::os::raw::c_uint = 35085;
pub const ETH_P_FIP: ::std::os::raw::c_uint = 35092;
pub const ETH_P_80221: ::std::os::raw::c_uint = 35095;
pub const ETH_P_LOOPBACK: ::std::os::raw::c_uint = 36864;
pub const ETH_P_QINQ1: ::std::os::raw::c_uint = 37120;
pub const ETH_P_QINQ2: ::std::os::raw::c_uint = 37376;
pub const ETH_P_QINQ3: ::std::os::raw::c_uint = 37632;
pub const ETH_P_EDSA: ::std::os::raw::c_uint = 56026;
pub const ETH_P_AF_IUCV: ::std::os::raw::c_uint = 64507;
pub const ETH_P_802_3_MIN: ::std::os::raw::c_uint = 1536;
pub const ETH_P_802_3: ::std::os::raw::c_uint = 1;
pub const ETH_P_AX25: ::std::os::raw::c_uint = 2;
pub const ETH_P_ALL: ::std::os::raw::c_uint = 3;
pub const ETH_P_802_2: ::std::os::raw::c_uint = 4;
pub const ETH_P_SNAP: ::std::os::raw::c_uint = 5;
pub const ETH_P_DDCMP: ::std::os::raw::c_uint = 6;
pub const ETH_P_WAN_PPP: ::std::os::raw::c_uint = 7;
pub const ETH_P_PPP_MP: ::std::os::raw::c_uint = 8;
pub const ETH_P_LOCALTALK: ::std::os::raw::c_uint = 9;
pub const ETH_P_CAN: ::std::os::raw::c_uint = 12;
pub const ETH_P_CANFD: ::std::os::raw::c_uint = 13;
pub const ETH_P_PPPTALK: ::std::os::raw::c_uint = 16;
pub const ETH_P_TR_802_2: ::std::os::raw::c_uint = 17;
pub const ETH_P_MOBITEX: ::std::os::raw::c_uint = 21;
pub const ETH_P_CONTROL: ::std::os::raw::c_uint = 22;
pub const ETH_P_IRDA: ::std::os::raw::c_uint = 23;
pub const ETH_P_ECONET: ::std::os::raw::c_uint = 24;
pub const ETH_P_HDLC: ::std::os::raw::c_uint = 25;
pub const ETH_P_ARCNET: ::std::os::raw::c_uint = 26;
pub const ETH_P_DSA: ::std::os::raw::c_uint = 27;
pub const ETH_P_TRAILER: ::std::os::raw::c_uint = 28;
pub const ETH_P_PHONET: ::std::os::raw::c_uint = 245;
pub const ETH_P_IEEE802154: ::std::os::raw::c_uint = 246;
pub const ETH_P_CAIF: ::std::os::raw::c_uint = 247;
pub const ETH_P_XDSA: ::std::os::raw::c_uint = 248;
pub const BPF_LD: ::std::os::raw::c_uint = 0;
pub const BPF_LDX: ::std::os::raw::c_uint = 1;
pub const BPF_ST: ::std::os::raw::c_uint = 2;
pub const BPF_STX: ::std::os::raw::c_uint = 3;
pub const BPF_ALU: ::std::os::raw::c_uint = 4;
pub const BPF_JMP: ::std::os::raw::c_uint = 5;
pub const BPF_RET: ::std::os::raw::c_uint = 6;
pub const BPF_MISC: ::std::os::raw::c_uint = 7;
pub const BPF_W: ::std::os::raw::c_uint = 0;
pub const BPF_H: ::std::os::raw::c_uint = 8;
pub const BPF_B: ::std::os::raw::c_uint = 16;
pub const BPF_IMM: ::std::os::raw::c_uint = 0;
pub const BPF_ABS: ::std::os::raw::c_uint = 32;
pub const BPF_IND: ::std::os::raw::c_uint = 64;
pub const BPF_MEM: ::std::os::raw::c_uint = 96;
pub const BPF_LEN: ::std::os::raw::c_uint = 128;
pub const BPF_MSH: ::std::os::raw::c_uint = 160;
pub const BPF_ADD: ::std::os::raw::c_uint = 0;
pub const BPF_SUB: ::std::os::raw::c_uint = 16;
pub const BPF_MUL: ::std::os::raw::c_uint = 32;
pub const BPF_DIV: ::std::os::raw::c_uint = 48;
pub const BPF_OR: ::std::os::raw::c_uint = 64;
pub const BPF_AND: ::std::os::raw::c_uint = 80;
pub const BPF_LSH: ::std::os::raw::c_uint = 96;
pub const BPF_RSH: ::std::os::raw::c_uint = 112;
pub const BPF_NEG: ::std::os::raw::c_uint = 128;
pub const BPF_MOD: ::std::os::raw::c_uint = 144;
pub const BPF_XOR: ::std::os::raw::c_uint = 160;
pub const BPF_JA: ::std::os::raw::c_uint = 0;
pub const BPF_JEQ: ::std::os::raw::c_uint = 16;
pub const BPF_JGT: ::std::os::raw::c_uint = 32;
pub const BPF_JGE: ::std::os::raw::c_uint = 48;
pub const BPF_JSET: ::std::os::raw::c_uint = 64;
pub const BPF_K: ::std::os::raw::c_uint = 0;
pub const BPF_X: ::std::os::raw::c_uint = 8;
pub const BPF_MAXINSNS: ::std::os::raw::c_uint = 4096;
pub const BPF_MAJOR_VERSION: ::std::os::raw::c_uint = 1;
pub const BPF_MINOR_VERSION: ::std::os::raw::c_uint = 1;
pub const BPF_A: ::std::os::raw::c_uint = 16;
pub const BPF_TAX: ::std::os::raw::c_uint = 0;
pub const BPF_TXA: ::std::os::raw::c_uint = 128;
pub const BPF_MEMWORDS: ::std::os::raw::c_uint = 16;
pub const SKF_AD_OFF: ::std::os::raw::c_int = -4096;
pub const SKF_AD_PROTOCOL: ::std::os::raw::c_uint = 0;
pub const SKF_AD_PKTTYPE: ::std::os::raw::c_uint = 4;
pub const SKF_AD_IFINDEX: ::std::os::raw::c_uint = 8;
pub const SKF_AD_NLATTR: ::std::os::raw::c_uint = 12;
pub const SKF_AD_NLATTR_NEST: ::std::os::raw::c_uint = 16;
pub const SKF_AD_MARK: ::std::os::raw::c_uint = 20;
pub const SKF_AD_QUEUE: ::std::os::raw::c_uint = 24;
pub const SKF_AD_HATYPE: ::std::os::raw::c_uint = 28;
pub const SKF_AD_RXHASH: ::std::os::raw::c_uint = 32;
pub const SKF_AD_CPU: ::std::os::raw::c_uint = 36;
pub const SKF_AD_ALU_XOR_X: ::std::os::raw::c_uint = 40;
pub const SKF_AD_VLAN_TAG: ::std::os::raw::c_uint = 44;
pub const SKF_AD_VLAN_TAG_PRESENT: ::std::os::raw::c_uint = 48;
pub const SKF_AD_PAY_OFFSET: ::std::os::raw::c_uint = 52;
pub const SKF_AD_RANDOM: ::std::os::raw::c_uint = 56;
pub const SKF_AD_VLAN_TPID: ::std::os::raw::c_uint = 60;
pub const SKF_AD_MAX: ::std::os::raw::c_uint = 64;
pub const SKF_NET_OFF: ::std::os::raw::c_int = -1048576;
pub const SKF_LL_OFF: ::std::os::raw::c_int = -2097152;
pub const BPF_NET_OFF: ::std::os::raw::c_int = -1048576;
pub const BPF_LL_OFF: ::std::os::raw::c_int = -2097152;
pub const TUN_READQ_SIZE: ::std::os::raw::c_uint = 500;
pub const TUN_TYPE_MASK: ::std::os::raw::c_uint = 15;
pub const IFF_TUN: ::std::os::raw::c_uint = 1;
pub const IFF_TAP: ::std::os::raw::c_uint = 2;
pub const IFF_NO_PI: ::std::os::raw::c_uint = 4096;
pub const IFF_ONE_QUEUE: ::std::os::raw::c_uint = 8192;
pub const IFF_VNET_HDR: ::std::os::raw::c_uint = 16384;
pub const IFF_TUN_EXCL: ::std::os::raw::c_uint = 32768;
pub const IFF_MULTI_QUEUE: ::std::os::raw::c_uint = 256;
pub const IFF_ATTACH_QUEUE: ::std::os::raw::c_uint = 512;
pub const IFF_DETACH_QUEUE: ::std::os::raw::c_uint = 1024;
pub const IFF_PERSIST: ::std::os::raw::c_uint = 2048;
pub const IFF_NOFILTER: ::std::os::raw::c_uint = 4096;
pub const TUN_TX_TIMESTAMP: ::std::os::raw::c_uint = 1;
pub const TUN_F_CSUM: ::std::os::raw::c_uint = 1;
pub const TUN_F_TSO4: ::std::os::raw::c_uint = 2;
pub const TUN_F_TSO6: ::std::os::raw::c_uint = 4;
pub const TUN_F_TSO_ECN: ::std::os::raw::c_uint = 8;
pub const TUN_F_UFO: ::std::os::raw::c_uint = 16;
pub const TUN_PKT_STRIP: ::std::os::raw::c_uint = 1;
pub const TUN_FLT_ALLMULTI: ::std::os::raw::c_uint = 1;
pub type __s8 = ::std::os::raw::c_schar;
pub type __u8 = ::std::os::raw::c_uchar;
pub type __s16 = ::std::os::raw::c_short;
pub type __u16 = ::std::os::raw::c_ushort;
pub type __s32 = ::std::os::raw::c_int;
pub type __u32 = ::std::os::raw::c_uint;
pub type __s64 = ::std::os::raw::c_longlong;
pub type __u64 = ::std::os::raw::c_ulonglong;
#[repr(C)]
#[derive(Debug, Default, Copy)]
pub struct __kernel_fd_set {
    pub fds_bits: [::std::os::raw::c_ulong; 16usize],
}
#[test]
fn bindgen_test_layout___kernel_fd_set() {
    assert_eq!(::std::mem::size_of::<__kernel_fd_set>() , 128usize , concat !
               ( "Size of: " , stringify ! ( __kernel_fd_set ) ));
    assert_eq! (::std::mem::align_of::<__kernel_fd_set>() , 8usize , concat !
                ( "Alignment of " , stringify ! ( __kernel_fd_set ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const __kernel_fd_set ) ) . fds_bits as * const
                _ as usize } , 0usize , concat ! (
                "Alignment of field: " , stringify ! ( __kernel_fd_set ) ,
                "::" , stringify ! ( fds_bits ) ));
}
impl Clone for __kernel_fd_set {
    fn clone(&self) -> Self { *self }
}
pub type __kernel_sighandler_t =
    ::std::option::Option<unsafe extern "C" fn(arg1: ::std::os::raw::c_int)>;
pub type __kernel_key_t = ::std::os::raw::c_int;
pub type __kernel_mqd_t = ::std::os::raw::c_int;
pub type __kernel_old_uid_t = ::std::os::raw::c_ushort;
pub type __kernel_old_gid_t = ::std::os::raw::c_ushort;
pub type __kernel_old_dev_t = ::std::os::raw::c_ulong;
pub type __kernel_long_t = ::std::os::raw::c_long;
pub type __kernel_ulong_t = ::std::os::raw::c_ulong;
pub type __kernel_ino_t = __kernel_ulong_t;
pub type __kernel_mode_t = ::std::os::raw::c_uint;
pub type __kernel_pid_t = ::std::os::raw::c_int;
pub type __kernel_ipc_pid_t = ::std::os::raw::c_int;
pub type __kernel_uid_t = ::std::os::raw::c_uint;
pub type __kernel_gid_t = ::std::os::raw::c_uint;
pub type __kernel_suseconds_t = __kernel_long_t;
pub type __kernel_daddr_t = ::std::os::raw::c_int;
pub type __kernel_uid32_t = ::std::os::raw::c_uint;
pub type __kernel_gid32_t = ::std::os::raw::c_uint;
pub type __kernel_size_t = __kernel_ulong_t;
pub type __kernel_ssize_t = __kernel_long_t;
pub type __kernel_ptrdiff_t = __kernel_long_t;
#[repr(C)]
#[derive(Debug, Default, Copy)]
pub struct __kernel_fsid_t {
    pub val: [::std::os::raw::c_int; 2usize],
}
#[test]
fn bindgen_test_layout___kernel_fsid_t() {
    assert_eq!(::std::mem::size_of::<__kernel_fsid_t>() , 8usize , concat ! (
               "Size of: " , stringify ! ( __kernel_fsid_t ) ));
    assert_eq! (::std::mem::align_of::<__kernel_fsid_t>() , 4usize , concat !
                ( "Alignment of " , stringify ! ( __kernel_fsid_t ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const __kernel_fsid_t ) ) . val as * const _ as
                usize } , 0usize , concat ! (
                "Alignment of field: " , stringify ! ( __kernel_fsid_t ) ,
                "::" , stringify ! ( val ) ));
}
impl Clone for __kernel_fsid_t {
    fn clone(&self) -> Self { *self }
}
pub type __kernel_off_t = __kernel_long_t;
pub type __kernel_loff_t = ::std::os::raw::c_longlong;
pub type __kernel_time_t = __kernel_long_t;
pub type __kernel_clock_t = __kernel_long_t;
pub type __kernel_timer_t = ::std::os::raw::c_int;
pub type __kernel_clockid_t = ::std::os::raw::c_int;
pub type __kernel_caddr_t = *mut ::std::os::raw::c_char;
pub type __kernel_uid16_t = ::std::os::raw::c_ushort;
pub type __kernel_gid16_t = ::std::os::raw::c_ushort;
pub type __le16 = __u16;
pub type __be16 = __u16;
pub type __le32 = __u32;
pub type __be32 = __u32;
pub type __le64 = __u64;
pub type __be64 = __u64;
pub type __sum16 = __u16;
pub type __wsum = __u32;
#[repr(C, packed)]
#[derive(Debug, Default, Copy)]
pub struct ethhdr {
    pub h_dest: [::std::os::raw::c_uchar; 6usize],
    pub h_source: [::std::os::raw::c_uchar; 6usize],
    pub h_proto: __be16,
}
#[test]
fn bindgen_test_layout_ethhdr() {
    assert_eq!(::std::mem::size_of::<ethhdr>() , 14usize , concat ! (
               "Size of: " , stringify ! ( ethhdr ) ));
    assert_eq! (::std::mem::align_of::<ethhdr>() , 1usize , concat ! (
                "Alignment of " , stringify ! ( ethhdr ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const ethhdr ) ) . h_dest as * const _ as usize
                } , 0usize , concat ! (
                "Alignment of field: " , stringify ! ( ethhdr ) , "::" ,
                stringify ! ( h_dest ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const ethhdr ) ) . h_source as * const _ as
                usize } , 6usize , concat ! (
                "Alignment of field: " , stringify ! ( ethhdr ) , "::" ,
                stringify ! ( h_source ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const ethhdr ) ) . h_proto as * const _ as
                usize } , 12usize , concat ! (
                "Alignment of field: " , stringify ! ( ethhdr ) , "::" ,
                stringify ! ( h_proto ) ));
}
impl Clone for ethhdr {
    fn clone(&self) -> Self { *self }
}
#[repr(C)]
#[derive(Debug, Default, Copy)]
pub struct sock_filter {
    pub code: __u16,
    pub jt: __u8,
    pub jf: __u8,
    pub k: __u32,
}
#[test]
fn bindgen_test_layout_sock_filter() {
    assert_eq!(::std::mem::size_of::<sock_filter>() , 8usize , concat ! (
               "Size of: " , stringify ! ( sock_filter ) ));
    assert_eq! (::std::mem::align_of::<sock_filter>() , 4usize , concat ! (
                "Alignment of " , stringify ! ( sock_filter ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const sock_filter ) ) . code as * const _ as
                usize } , 0usize , concat ! (
                "Alignment of field: " , stringify ! ( sock_filter ) , "::" ,
                stringify ! ( code ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const sock_filter ) ) . jt as * const _ as
                usize } , 2usize , concat ! (
                "Alignment of field: " , stringify ! ( sock_filter ) , "::" ,
                stringify ! ( jt ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const sock_filter ) ) . jf as * const _ as
                usize } , 3usize , concat ! (
                "Alignment of field: " , stringify ! ( sock_filter ) , "::" ,
                stringify ! ( jf ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const sock_filter ) ) . k as * const _ as usize
                } , 4usize , concat ! (
                "Alignment of field: " , stringify ! ( sock_filter ) , "::" ,
                stringify ! ( k ) ));
}
impl Clone for sock_filter {
    fn clone(&self) -> Self { *self }
}
#[repr(C)]
#[derive(Debug, Copy)]
pub struct sock_fprog {
    pub len: ::std::os::raw::c_ushort,
    pub filter: *mut sock_filter,
}
#[test]
fn bindgen_test_layout_sock_fprog() {
    assert_eq!(::std::mem::size_of::<sock_fprog>() , 16usize , concat ! (
               "Size of: " , stringify ! ( sock_fprog ) ));
    assert_eq! (::std::mem::align_of::<sock_fprog>() , 8usize , concat ! (
                "Alignment of " , stringify ! ( sock_fprog ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const sock_fprog ) ) . len as * const _ as
                usize } , 0usize , concat ! (
                "Alignment of field: " , stringify ! ( sock_fprog ) , "::" ,
                stringify ! ( len ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const sock_fprog ) ) . filter as * const _ as
                usize } , 8usize , concat ! (
                "Alignment of field: " , stringify ! ( sock_fprog ) , "::" ,
                stringify ! ( filter ) ));
}
impl Clone for sock_fprog {
    fn clone(&self) -> Self { *self }
}
impl Default for sock_fprog {
    fn default() -> Self { unsafe { ::std::mem::zeroed() } }
}
#[repr(C)]
#[derive(Debug, Default, Copy)]
pub struct tun_pi {
    pub flags: __u16,
    pub proto: __be16,
}
#[test]
fn bindgen_test_layout_tun_pi() {
    assert_eq!(::std::mem::size_of::<tun_pi>() , 4usize , concat ! (
               "Size of: " , stringify ! ( tun_pi ) ));
    assert_eq! (::std::mem::align_of::<tun_pi>() , 2usize , concat ! (
                "Alignment of " , stringify ! ( tun_pi ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const tun_pi ) ) . flags as * const _ as usize
                } , 0usize , concat ! (
                "Alignment of field: " , stringify ! ( tun_pi ) , "::" ,
                stringify ! ( flags ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const tun_pi ) ) . proto as * const _ as usize
                } , 2usize , concat ! (
                "Alignment of field: " , stringify ! ( tun_pi ) , "::" ,
                stringify ! ( proto ) ));
}
impl Clone for tun_pi {
    fn clone(&self) -> Self { *self }
}
#[repr(C)]
#[derive(Debug, Default, Copy)]
pub struct tun_filter {
    pub flags: __u16,
    pub count: __u16,
    pub addr: __IncompleteArrayField<[__u8; 6usize]>,
}
#[test]
fn bindgen_test_layout_tun_filter() {
    assert_eq!(::std::mem::size_of::<tun_filter>() , 4usize , concat ! (
               "Size of: " , stringify ! ( tun_filter ) ));
    assert_eq! (::std::mem::align_of::<tun_filter>() , 2usize , concat ! (
                "Alignment of " , stringify ! ( tun_filter ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const tun_filter ) ) . flags as * const _ as
                usize } , 0usize , concat ! (
                "Alignment of field: " , stringify ! ( tun_filter ) , "::" ,
                stringify ! ( flags ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const tun_filter ) ) . count as * const _ as
                usize } , 2usize , concat ! (
                "Alignment of field: " , stringify ! ( tun_filter ) , "::" ,
                stringify ! ( count ) ));
    assert_eq! (unsafe {
                & ( * ( 0 as * const tun_filter ) ) . addr as * const _ as
                usize } , 4usize , concat ! (
                "Alignment of field: " , stringify ! ( tun_filter ) , "::" ,
                stringify ! ( addr ) ));
}
impl Clone for tun_filter {
    fn clone(&self) -> Self { *self }
}
