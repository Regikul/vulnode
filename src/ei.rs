#![allow(dead_code)]

extern crate ei_sys;

use std::mem::MaybeUninit;
use std::ffi::{CStr, CString, c_void};
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::{Result as IOResult, Error};

use in_addr;

pub use ei_sys::{ErlConnect, erlang_char_encoding, ERLANG_ASCII, ERLANG_LATIN1, ERLANG_UTF8};

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

type SocketPort = i32;
type FileDescr = i32;

const ZERO_BYTE_MSG:&str = "String should not contain zero-byte";

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
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let code = match self.btype {
            NodeBuilderType::SMALL => {
                unsafe { ei_sys::ei_connect_init(node.as_mut_ptr(), nodename.as_ptr(), cookie.as_ptr(), secs as i16) }
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

    pub fn listen(self: &mut ErlangNode, port: Option<i32>, backlog: i32) -> IOResult<(FileDescr, SocketPort)> {
        let mut actual_port = port.unwrap_or(0);
        let ret = unsafe {
            ei_sys::ei_listen(&mut self.cnode, &mut actual_port, backlog)
        };
        if ret == ei_sys::ERL_ERROR {
            Err(Error::from_raw_os_error(error_code()))
        } else {
            Ok((ret, actual_port))
        }
    }

    pub fn accept(self: &mut ErlangNode, listensock: FileDescr) -> Result<(i32, ErlConnect), i32> {
        let mut mem = MaybeUninit::<ErlConnect>::uninit();
        let ret = unsafe {
            ei_sys::ei_accept(&mut self.cnode, listensock, mem.as_mut_ptr())
        };
        if ret == ei_sys::ERL_ERROR {
            Err(error_code())
        } else {
            let conn: ErlConnect = unsafe {mem.assume_init()};
            Ok((ret, conn))
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

type Arity = i32;
pub enum ErlangType {
    Integer,
    Float,
    Atom(Arity),
    Reference,
    Port,
    Pid,
    Tuple(Arity),
    String(Arity),
    List(Arity),
    Binary(Arity),
    BitBinary(Arity),
    BigInt(Arity),
    Function,
    Map(Arity),
    NotImplemented,
}

#[derive(Debug)]
pub enum ErlangTypeError {
    CanNotGetType,
    TypeDiffers,
    DecodeFails,
}

#[derive(Debug)]
pub enum ErlangMsgType {
    Send,
    RegSend,
    Link,
    Unlink,
    Exit,
    Unknown
}

#[derive(Debug)]
pub enum ErlangRecvError {
    TryAgain,
    SomeError,
}

pub struct ErlangRef(ei_sys::erlang_ref);
pub struct ErlangPid(ei_sys::erlang_pid);
pub struct ErlangPort(ei_sys::erlang_port);
pub struct ErlangTraceToken(ei_sys::erlang_trace);
pub struct ErlangMsg(ei_sys::erlang_msg);

impl ErlangMsg {
    pub fn get_type(&self) -> ErlangMsgType {
        match self.0.msgtype as u8 {
            ei_sys::ERL_SEND => ErlangMsgType::Send,
            ei_sys::ERL_REG_SEND => ErlangMsgType::RegSend,
            ei_sys::ERL_LINK => ErlangMsgType::Link,
            ei_sys::ERL_UNLINK => ErlangMsgType::Unlink,
            ei_sys::ERL_EXIT => ErlangMsgType::Exit,
            _ => ErlangMsgType::Unknown,
        }
    }

    pub fn from(&self) -> ErlangPid {
        ErlangPid(self.0.from)
    }

    pub fn to(&self) -> ErlangPid {
        ErlangPid(self.0.to)
    }

    pub fn toname(&self) -> String {
        let cstr = unsafe {CStr::from_ptr(self.0.toname.as_ptr())};
        cstr.to_owned().into_string().expect("can not cast toname from C-string to Rust-string")
    }

    pub fn cookie(&self) -> String {
        let cstr = unsafe {CStr::from_ptr(self.0.cookie.as_ptr())};
        cstr.to_owned().into_string().expect("can not cast cookie from C-string to Rust-string")
    }

    pub fn trace_token(&self) -> ErlangTraceToken {
        ErlangTraceToken(self.0.token.clone())
    }
}

pub struct XBuf {
    xbuf: ei_sys::ei_x_buff
}

impl XBuf {
    pub fn new() -> XBuf {
        let mut mem = MaybeUninit::<ei_sys::ei_x_buff>::uninit();
        unsafe {
            ei_sys::ei_x_new(mem.as_mut_ptr());
        }
        XBuf{
            xbuf: unsafe {mem.assume_init()}
        }
    }

    pub fn new_with_version() -> XBuf {
        let mut mem = MaybeUninit::<ei_sys::ei_x_buff>::uninit();
        unsafe {
            ei_sys::ei_x_new_with_version(mem.as_mut_ptr());
        }
        XBuf{
            xbuf: unsafe {mem.assume_init()}
        }
    }

    pub fn free(&mut self) {
        unsafe {ei_sys::ei_x_free(&mut self.xbuf)};
    }

    pub fn receive_msg(&mut self, fd: i32) -> Result<ErlangMsg, ErlangRecvError> {
        let mut msg_mem = MaybeUninit::<ei_sys::erlang_msg>::uninit();
        let erl_code = unsafe {
            ei_sys::ei_xreceive_msg(fd, msg_mem.as_mut_ptr(), &mut self.xbuf)
        };
        if erl_code == ei_sys::ERL_ERROR {
            Err(ErlangRecvError::SomeError)
        } else if erl_code == ei_sys::ERL_TICK {
            Err(ErlangRecvError::TryAgain)
        } else {
            Ok(ErlangMsg(unsafe {msg_mem.assume_init()}))
        }
    }

    pub fn append(&mut self, other: &mut XBuf) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_append(&mut self.xbuf, &mut other.xbuf);
        };
        self
    }

    pub fn append_buf(&mut self, other: &[u8]) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_append_buf(&mut self.xbuf, other.as_ptr() as *const i8, other.len() as i32);
        };
        self
    }

    pub fn encode_atom(&mut self, atom: &str) -> &mut XBuf {
        let zstr = CString::new(atom).expect(ZERO_BYTE_MSG);
        unsafe {
            ei_sys::ei_x_encode_atom(&mut self.xbuf, zstr.as_ptr() as *const i8)
        };
        self
    }

    pub fn encode_atom_as(&mut self, atom: &str, from_enc: ei_sys::erlang_char_encoding, to_enc: ei_sys::erlang_char_encoding) -> &mut XBuf {
        let zstr = CString::new(atom).expect(ZERO_BYTE_MSG);
        unsafe {
            ei_sys::ei_x_encode_atom_as(&mut self.xbuf, zstr.as_ptr() as *const i8, from_enc, to_enc);
        };
        self
    }

    pub fn encode_atom_len(&mut self, chars: &str, len: i32) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_atom_len(&mut self.xbuf, chars.as_ptr() as *const i8, len as i32);
        };
        self
    }


    pub fn encode_atom_len_as(&mut self, chars: &str, len: i32, from_enc: ei_sys::erlang_char_encoding, to_enc: ei_sys::erlang_char_encoding) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_atom_len_as(&mut self.xbuf, chars.as_ptr() as *const i8, len, from_enc, to_enc);
        };
        self
    }

    pub fn encode_binary(&mut self, p: &[u8]) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_binary(&mut self.xbuf, p.as_ptr() as *const c_void, p.len() as i32)
        };
        self
    }

    pub fn encode_bitstring(&mut self, p: &[u8], bitoffs: isize, nbits: isize) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_bitstring(&mut self.xbuf, p.as_ptr() as *const i8, bitoffs, nbits)
        };
        self
    }

    pub fn encode_boolean(&mut self, b: bool) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_boolean(&mut self.xbuf, b as i32)
        };
        self
    }

    pub fn encode_char(&mut self, c: u8) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_char(&mut self.xbuf, c as i8)
        };
        self
    }

    pub fn encode_double(&mut self, d: f64) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_double(&mut self.xbuf, d)
        };
        self
    }

    pub fn encode_empty_list(&mut self) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_empty_list(&mut self.xbuf)
        };
        self
    }

    pub fn encode_erlang_fun(&mut self, fun: &ei_sys::erlang_fun) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_fun(&mut self.xbuf, fun)
        };
        self
    }

    pub fn encode_list_header(&mut self, arity: i64) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_list_header(&mut self.xbuf, arity)
        };
        self
    }

    pub fn encode_long(&mut self, n: i64) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_long(&mut self.xbuf, n)
        };
        self
    }

    pub fn encode_list_longlong(&mut self, n: i64) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_longlong(&mut self.xbuf, n)
        };
        self
    }

    pub fn encode_map_header(&mut self, arity: i64) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_map_header(&mut self.xbuf, arity)
        };
        self
    }

    pub fn encode_pid(&mut self, pid: &ei_sys::erlang_pid) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_pid(&mut self.xbuf, pid)
        };
        self
    }

    pub fn encode_port(&mut self, port: &ei_sys::erlang_port) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_port(&mut self.xbuf, port)
        };
        self
    }

    pub fn encode_ref(&mut self, eref: &ei_sys::erlang_ref) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_ref(&mut self.xbuf, eref)
        };
        self
    }

    pub fn encode_string(&mut self, string: &str) -> &mut XBuf {
        let s: CString = CString::new(string).expect(ZERO_BYTE_MSG);
        unsafe {
            ei_sys::ei_x_encode_string(&mut self.xbuf, s.as_ptr() as *const i8)
        };
        self
    }

    pub fn encode_string_len(&mut self, string: &str, len: i32) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_string_len(&mut self.xbuf, string.as_ptr() as *const i8, len)
        };
        self
    }

    pub fn encode_trace(&mut self, trace: &ei_sys::erlang_trace) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_trace(&mut self.xbuf, trace)
        };
        self
    }

    pub fn encode_tuple_header(&mut self, arity: i64) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_tuple_header(&mut self.xbuf, arity)
        };
        self
    }

    pub fn encode_ulong(&mut self, long: u64) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_ulong(&mut self.xbuf, long)
        };
        self
    }

    pub fn encode_ulonglong(&mut self, long: u64) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_ulonglong(&mut self.xbuf, long)
        };
        self
    }

    pub fn encode_version(&mut self) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_version(&mut self.xbuf)
        };
        self
    }

    pub fn reset_index(&mut self) -> &mut XBuf {
        self.xbuf.index = 0;
        self
    }

    pub fn get_type(&mut self) -> Result<ErlangType, ErlangTypeError> {
        let mut typ: i32 = 0;
        let mut size:i32 = 0;
        let get_type_ret = unsafe {
            ei_sys::ei_get_type(self.xbuf.buff, &self.xbuf.index, &mut typ, &mut size)
        };
        let ret = match typ as u8 {
            ei_sys::ERL_SMALL_INTEGER_EXT | ei_sys::ERL_INTEGER_EXT => ErlangType::Integer,
            ei_sys::ERL_FLOAT_EXT | ei_sys::NEW_FLOAT_EXT => ErlangType::Float,
            ei_sys::ERL_ATOM_EXT | ei_sys::ERL_SMALL_ATOM_EXT | ei_sys::ERL_ATOM_UTF8_EXT | ei_sys::ERL_SMALL_ATOM_UTF8_EXT => ErlangType::Atom(size),
            ei_sys::ERL_REFERENCE_EXT | ei_sys::ERL_NEW_REFERENCE_EXT | ei_sys::ERL_NEWER_REFERENCE_EXT => ErlangType::Reference,
            ei_sys::ERL_PORT_EXT | ei_sys::ERL_NEW_PORT_EXT => ErlangType::Port,
            ei_sys::ERL_PID_EXT | ei_sys::ERL_NEW_PID_EXT => ErlangType::Pid,
            ei_sys::ERL_SMALL_TUPLE_EXT | ei_sys::ERL_LARGE_TUPLE_EXT => ErlangType::Tuple(size),
            ei_sys::ERL_STRING_EXT => ErlangType::String(size),
            ei_sys::ERL_LIST_EXT => ErlangType::List(size),
            ei_sys::ERL_BINARY_EXT => ErlangType::Binary(size),
            ei_sys::ERL_BIT_BINARY_EXT => ErlangType::Binary(size),
            ei_sys::ERL_SMALL_BIG_EXT | ei_sys::ERL_LARGE_BIG_EXT => ErlangType::BigInt(size),
            ei_sys::ERL_FUN_EXT | ei_sys::ERL_NEW_FUN_EXT => ErlangType::Function,
            ei_sys::ERL_MAP_EXT => ErlangType::Map(size),
            ei_sys::ERL_EXPORT_EXT | ei_sys::ERL_NIL_EXT | _ => ErlangType::NotImplemented,
        };
        if get_type_ret == ei_sys::ERL_ERROR {
            Err(ErlangTypeError::CanNotGetType)
        } else {
            Ok(ret)
        }
    }

    pub fn decode_version(&mut self) -> Option<i32> {
        let mut version:i32 = 0;
        let ret = unsafe {
            ei_sys::ei_decode_version(self.xbuf.buff, &mut self.xbuf.index, &mut version)
        };
        match_ret(ret, version)
    }

    pub fn decode_atom(&mut self) -> Result<String, ErlangTypeError> {
        self.get_type().and_then(|ty: ErlangType| {
                if let ErlangType::Atom(arity) = ty {
                    let name_len = (arity + 1) as usize;
                    let mut atom_bytes = Vec::<u8>::with_capacity(name_len);
                    let erl_code = unsafe {
                        atom_bytes.set_len(name_len);
                        ei_sys::ei_decode_atom(self.xbuf.buff, &mut self.xbuf.index, atom_bytes.as_mut_ptr() as *mut i8)
                    };
                    if erl_code == ei_sys::ERL_ERROR {
                        Err(ErlangTypeError::DecodeFails)
                    } else {
                        CStr::from_bytes_with_nul(atom_bytes.as_slice())
                            .map_err(|_| {ErlangTypeError::DecodeFails})
                            .and_then(|cstr| {
                                cstr.to_str()
                                    .map_err(|_| {ErlangTypeError::DecodeFails})
                            })
                            .map(|v|String::from(v))
                    }
                } else {
                    Err(ErlangTypeError::TypeDiffers)
                }
            })
    }

    pub fn decode_binary(&mut self) -> Result<Vec<u8>, ErlangTypeError> {
        self.get_type().and_then(|ty:ErlangType| {
            if let ErlangType::Binary(arity) = ty {
                let bin_size = arity as usize;
                let mut bin = Vec::<u8>::with_capacity(bin_size);
                let erl_code = unsafe {
                    let mut dummy = 0;
                    bin.set_len(bin_size);
                    ei_sys::ei_decode_binary(self.xbuf.buff, &mut self.xbuf.index, bin.as_mut_ptr() as *mut c_void, &mut dummy)
                };
                if erl_code == ei_sys::ERL_ERROR {
                    Err(ErlangTypeError::DecodeFails)
                } else {
                    Ok(bin)
                }
            } else {
                Err(ErlangTypeError::TypeDiffers)
            }
        })
    }

}

pub fn close_connection(fd: i32) {
    unsafe {
        ei_sys::ei_close_connection(fd)
    };
}


pub fn match_ret<T>(ret: i32, val: T) -> Option<T> {
    if ret == ei_sys::ERL_ERROR {
        None
    } else {
        Some(val)
    }
}

impl Drop for XBuf {
    fn drop(&mut self) {
        XBuf::free(self)
    }
}

