#![allow(dead_code)]

use std::mem::MaybeUninit;
use std::ffi::CString;
use in_addr;

pub use ei_sys::ErlConnect;

pub type CNode = ei_sys::ei_cnode;

pub struct ErlangNode {
    epmd_fd: Option<i32>,
    listen_port: Option<i32>,
    cnode: ei_sys::ei_cnode
}

enum NodeBuilderType {
    SMALL,
    EXTRA
}

pub struct NodeBuilder {
    btype: NodeBuilderType,

    cookie: Option<CString>,
    nodename: Option<CString>,

    alivename: Option<CString>,
    hostname: Option<CString>,
    addr: Option<in_addr::in_addr>
}

type Port = i32;
type FileDescr = i32;

impl NodeBuilder {
    pub fn new(cookie: &str, nodename: &str) -> NodeBuilder {
        NodeBuilder {
            btype: NodeBuilderType::SMALL,
            cookie: Some(CString::new(cookie).expect("bad cookie string")),
            nodename: Some(CString::new(nodename).expect("bad node name string")),
            alivename: None,
            hostname: None,
            addr: None,
        }
    }

    pub fn extra(self: &mut NodeBuilder, alivename: &str, hostname: &str, addr: in_addr::in_addr) -> &mut NodeBuilder {
        self.alivename = Some(CString::new(alivename).expect("bad name for the alive process"));
        self.hostname = Some(CString::new(hostname).expect("bad hostname given"));
        self.addr = Some(addr);
        self.btype = NodeBuilderType::EXTRA;
        self
    }

    pub fn connect_init(self: NodeBuilder) -> Result<ErlangNode, i32> {
        let mut node = MaybeUninit::<CNode>::uninit();
        let nodename = self.nodename.unwrap();
        let cookie = self.cookie.unwrap();
        let code = match self.btype {
            NodeBuilderType::SMALL => {
                unsafe { ei_sys::ei_connect_init(node.as_mut_ptr(), nodename.as_ptr(), cookie.as_ptr(), 0) }
            }
            NodeBuilderType::EXTRA => {
                let alivename = self.alivename.unwrap();
                let hostname = self.hostname.unwrap();
                let mut ip = self.addr.unwrap();
                unsafe { 
                    ei_sys::ei_connect_xinit(
                        node.as_mut_ptr(),
                        hostname.as_ptr(),
                        alivename.as_ptr(),
                        nodename.as_ptr(),
                        &mut ip,
                        cookie.as_ptr(),
                        0
                    )
                }
            }
        };
        if code == ei_sys::ERL_ERROR {
            Err(error_code())
        } else {
            let cnode = unsafe {node.assume_init()};
            Ok(ErlangNode{
                cnode: cnode,
                epmd_fd: None,
                listen_port: None
            })
        }
    }
}

pub fn init() -> Result<(), i32> {
    let code = unsafe {ei_sys::ei_init()};
    if code == 0 {
        Ok(())
    } else {
        Err(code)
    }
}

pub fn error_code() -> i32 {
    unsafe {
        *ei_sys::__erl_errno_place()
    }
}

impl ErlangNode {

    pub fn listen(self: &mut ErlangNode, port: Option<i32>, backlog: i32) -> Result<(FileDescr, Port), i32> {
        let mut actual_port = port.unwrap_or(0);
        let ret = unsafe {
            ei_sys::ei_listen(&mut self.cnode, &mut actual_port, backlog)
        };
        if ret == ei_sys::ERL_ERROR {
            Err(error_code())
        } else {
            Ok((ret, actual_port))
        }
    }

    pub fn accept(self: &mut ErlangNode, listensock: FileDescr) -> Result<ErlConnect, i32> {
        let mut mem = MaybeUninit::<ErlConnect>::uninit();
        let ret = unsafe {
            ei_sys::ei_accept(&mut self.cnode, listensock, mem.as_mut_ptr())
        };
        if ret == ei_sys::ERL_ERROR {
            Err(error_code())
        } else {
            let conn: ErlConnect = unsafe {mem.assume_init()};
            Ok(conn)
        }
    }

    pub fn publish(self: &mut ErlangNode, port: i32) -> Result<FileDescr, i32> {
        let ret = unsafe {
            ei_sys::ei_publish(&mut self.cnode, port)
        };
        if ret == ei_sys::ERL_ERROR {
            Err(error_code())
        } else {
            self.epmd_fd = Some(ret);
            Ok(ret)
        }
    }

}

