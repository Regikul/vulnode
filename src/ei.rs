#![allow(dead_code)]

extern crate ei_sys;
use std::mem::MaybeUninit;
use std::ffi::{CStr, CString, c_void};
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::{Result as IOResult, Error, ErrorKind};

use in_addr;

pub use ei_sys::{ErlConnect, erlang_char_encoding, ERLANG_ASCII, ERLANG_LATIN1, ERLANG_UTF8};

pub type CNode = ei_sys::ei_cnode;

pub struct ErlangNode {
    epmd_fd: Option<i32>,
    listen_fd: Option<i32>,
    listen_port: Option<i32>,
    cnode: ei_sys::ei_cnode
}

pub struct ErlangConnection {
    pub socket: i32,
    pub remote_node: String
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

    pub fn connect_init(self: NodeBuilder) -> IOResult<ErlangNode> {
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
            Err(Error::from_raw_os_error(error_code()))
        } else {
            let cnode = unsafe {node.assume_init()};
            Ok(ErlangNode{
                cnode: cnode,
                epmd_fd: None,
                listen_port: None,
                listen_fd: None,
            })
        }
    }
}

pub fn init() -> IOResult<()> {
    let code = unsafe {ei_sys::ei_init()};
    if code == 0 {
        Ok(())
    } else {
        Err(Error::from_raw_os_error(error_code()))
    }
}

pub fn error_code() -> i32 {
    unsafe {
        *ei_sys::__erl_errno_place()
    }
}

impl ErlangNode {

    pub fn listen(&mut self, port: Option<i32>, backlog: i32) -> IOResult<FileDescr> {
        let mut actual_port = port.unwrap_or(0);
        let ret = unsafe {
            ei_sys::ei_listen(&mut self.cnode, &mut actual_port, backlog)
        };
        if ret == ei_sys::ERL_ERROR {
            Err(Error::from_raw_os_error(error_code()))
        } else {
            self.listen_port = Some(actual_port);
            self.listen_fd = Some(ret);
            Ok(ret)
        }
    }

    pub fn accept(&mut self, timeout: Option<u32>) -> IOResult<ErlangConnection> {
        self.listen_fd.ok_or(Error::from(ErrorKind::InvalidData))
            .and_then(|listensock|{
                        let mut mem = MaybeUninit::<ErlConnect>::uninit();
                        let ret = unsafe {
                            ei_sys::ei_accept_tmo(&mut self.cnode, listensock, mem.as_mut_ptr(), timeout.unwrap_or(0))
                        };
                        if ret == ei_sys::ERL_ERROR {
                            Err(Error::from_raw_os_error(error_code()))
                        } else {
                            let conn: ErlConnect = unsafe {mem.assume_init()};
                            let nodename = cstr2ruststr(&conn.nodename);
                            Ok(ErlangConnection{socket: ret, remote_node: nodename})
                        }
                    })
    }

    pub fn publish(&mut self, timeout: Option<u32>) -> IOResult<FileDescr> {
        self.listen_port.or_else(||{
            if self.listen(None, 10).is_ok() {
                self.listen_port
            } else {
                None
            }
        }).ok_or(Error::from(ErrorKind::InvalidData))
          .and_then(|port|{
            let ret = unsafe {
                ei_sys::ei_publish_tmo(&mut self.cnode, port, timeout.unwrap_or(0))
            };
            if ret == ei_sys::ERL_ERROR {
                Err(Error::from_raw_os_error(error_code()))
            } else {
                self.epmd_fd = Some(ret);
                Ok(ret)
            }
        })
    }

    pub fn unpublish(&mut self) {
        self.epmd_fd.map(
            |sock|close_connection(sock)
        );
    }

}

type Arity = i32;
#[derive(Debug)]
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
    EmptyList,
    Binary(Arity),
    BitBinary(Arity),
    BigInt(Arity),
    Function,
    Map(Arity),
    NotImplemented(u32),
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

    pub fn receive_msg(&mut self, fd: i32, timeout: Option<u32>) -> IOResult<ErlangMsg> {
        let mut msg_mem = MaybeUninit::<ei_sys::erlang_msg>::uninit();
        let erl_code = unsafe {
            ei_sys::ei_xreceive_msg_tmo(fd, msg_mem.as_mut_ptr(), &mut self.xbuf, timeout.unwrap_or(0))
        };
        if erl_code == ei_sys::ERL_ERROR {
            Err(Error::from_raw_os_error(error_code()))
        } else if erl_code == ei_sys::ERL_TICK {
            Err(Error::from_raw_os_error(error_code()))
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

    pub fn encode_pid(&mut self, pid: &ErlangPid) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_pid(&mut self.xbuf, &pid.0)
        };
        self
    }

    pub fn encode_port(&mut self, port: &ei_sys::erlang_port) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_port(&mut self.xbuf, port)
        };
        self
    }

    pub fn encode_ref(&mut self, eref: &ErlangRef) -> &mut XBuf {
        unsafe {
            ei_sys::ei_x_encode_ref(&mut self.xbuf, &eref.0)
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
            ei_sys::ERL_NIL_EXT => ErlangType::EmptyList,
            otherwise => ErlangType::NotImplemented(otherwise as u32),
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

    pub fn decode_binary_string(&mut self) -> Result<String, ErlangTypeError> {
        self.decode_binary()
            .and_then(|vec| {
                String::from_utf8(vec)
                    .map_err(|_| ErlangTypeError::DecodeFails)
            })
    }

    pub fn decode_string(&mut self) -> Result<String, ErlangTypeError> {
        self.get_type().and_then(|ty:ErlangType| {
            if let ErlangType::String(arity) = ty {
                let bin_size = arity as usize + 1;
                let mut bin = Vec::<u8>::with_capacity(bin_size);
                let erl_code = unsafe {
                    bin.set_len(bin_size);
                    ei_sys::ei_decode_string(self.xbuf.buff, &mut self.xbuf.index, bin.as_mut_ptr() as *mut i8)
                };
                if erl_code == ei_sys::ERL_ERROR {
                    Err(ErlangTypeError::DecodeFails)
                } else {
                    String::from_utf8(bin).map_err(|_| ErlangTypeError::DecodeFails)
                }
            } else {
                Err(ErlangTypeError::TypeDiffers)
            }
        })
    }

    pub fn decode_boolean(&mut self) -> Result<bool, ErlangTypeError> {
        self.get_type().and_then(|et:ErlangType| {
            if let ErlangType::Atom(_) = et {
                let mut bval = 0;
                let erl_code = unsafe {
                    ei_sys::ei_decode_boolean(self.xbuf.buff, &mut self.xbuf.index, &mut bval)
                };
                if erl_code == ei_sys::ERL_ERROR {
                    Err(ErlangTypeError::DecodeFails)
                } else {
                    Ok(bval != 0)
                }
            } else {
                Err(ErlangTypeError::TypeDiffers)
            }
        })
    }

    pub fn decode_char(&mut self) -> Result<u8, ErlangTypeError> {
        self.get_type().and_then(|et:ErlangType| {
            if let ErlangType::Integer = et {
                let mut val = 0;
                let erl_code = unsafe {
                    ei_sys::ei_decode_char(self.xbuf.buff, &mut self.xbuf.index, &mut val)
                };
                if erl_code == ei_sys::ERL_ERROR {
                    Err(ErlangTypeError::DecodeFails)
                } else {
                    Ok(val as u8)
                }
            } else {
                Err(ErlangTypeError::TypeDiffers)
            }
        })
    }

    pub fn decode_double(&mut self) -> Result<f64, ErlangTypeError> {
        self.get_type().and_then(|et:ErlangType| {
            if let ErlangType::Float = et {
                let mut val = Default::default();
                let erl_code = unsafe {
                    ei_sys::ei_decode_double(self.xbuf.buff, &mut self.xbuf.index, &mut val)
                };
                if erl_code == ei_sys::ERL_ERROR {
                    Err(ErlangTypeError::DecodeFails)
                } else {
                    Ok(val)
                }
            } else {
                Err(ErlangTypeError::TypeDiffers)
            }
        })
    }

    pub fn decode_list_header(&mut self) -> Result<i32, ErlangTypeError> {
        self.get_type().and_then(|et:ErlangType| {
            if let ErlangType::List(_) = et {
                let mut val = 0;
                let erl_code = unsafe {
                    ei_sys::ei_decode_list_header(self.xbuf.buff, &mut self.xbuf.index, &mut val)
                };
                if erl_code == ei_sys::ERL_ERROR {
                    Err(ErlangTypeError::DecodeFails)
                } else {
                    Ok(val)
                }
            } else {
                Err(ErlangTypeError::TypeDiffers)
            }
        })
    }

    pub fn decode_map_header(&mut self) -> Result<i32, ErlangTypeError> {
        self.get_type().and_then(|et:ErlangType| {
            if let ErlangType::Map(_) = et {
                let mut val = 0;
                let erl_code = unsafe {
                    ei_sys::ei_decode_map_header(self.xbuf.buff, &mut self.xbuf.index, &mut val)
                };
                if erl_code == ei_sys::ERL_ERROR {
                    Err(ErlangTypeError::DecodeFails)
                } else {
                    Ok(val)
                }
            } else {
                Err(ErlangTypeError::TypeDiffers)
            }
        })
    }

    pub fn decode_tuple_header(&mut self) -> Result<i32, ErlangTypeError> {
        self.get_type().and_then(|et:ErlangType| {
            if let ErlangType::Tuple(_) = et {
                let mut val = 0;
                let erl_code = unsafe {
                    ei_sys::ei_decode_tuple_header(self.xbuf.buff, &mut self.xbuf.index, &mut val)
                };
                if erl_code == ei_sys::ERL_ERROR {
                    Err(ErlangTypeError::DecodeFails)
                } else {
                    Ok(val)
                }
            } else {
                Err(ErlangTypeError::TypeDiffers)
            }
        })
    }

    pub fn decode_long(&mut self) -> Result<i64, ErlangTypeError> {
        self.get_type().and_then(|et:ErlangType| {
            if let ErlangType::Integer = et {
                let mut val = 0;
                let erl_code = unsafe {
                    ei_sys::ei_decode_long(self.xbuf.buff, &mut self.xbuf.index, &mut val)
                };
                if erl_code == ei_sys::ERL_ERROR {
                    Err(ErlangTypeError::DecodeFails)
                } else {
                    Ok(val)
                }
            } else {
                Err(ErlangTypeError::TypeDiffers)
            }
        })
    }

    pub fn decode_ulong(&mut self) -> Result<u64, ErlangTypeError> {
        self.get_type().and_then(|et:ErlangType| {
            if let ErlangType::Integer = et {
                let mut val = 0;
                let erl_code = unsafe {
                    ei_sys::ei_decode_ulong(self.xbuf.buff, &mut self.xbuf.index, &mut val)
                };
                if erl_code == ei_sys::ERL_ERROR {
                    Err(ErlangTypeError::DecodeFails)
                } else {
                    Ok(val)
                }
            } else {
                Err(ErlangTypeError::TypeDiffers)
            }
        })
    }

    pub fn decode_pid(&mut self) -> Result<ErlangPid, ErlangTypeError> {
        self.get_type().and_then(|et:ErlangType| {
            if let ErlangType::Pid = et {
                let mut val = MaybeUninit::<ei_sys::erlang_pid>::uninit();
                let erl_code = unsafe {
                    ei_sys::ei_decode_pid(self.xbuf.buff, &mut self.xbuf.index, val.as_mut_ptr())
                };
                if erl_code == ei_sys::ERL_ERROR {
                    Err(ErlangTypeError::DecodeFails)
                } else {
                    Ok(ErlangPid(unsafe {val.assume_init()}))
                }
            } else {
                Err(ErlangTypeError::TypeDiffers)
            }
        })
    }

    pub fn decode_ref(&mut self) -> Result<ErlangRef, ErlangTypeError> {
        self.get_type().and_then(|et:ErlangType| {
            if let ErlangType::Pid = et {
                let mut val = MaybeUninit::<ei_sys::erlang_ref>::uninit();
                let erl_code = unsafe {
                    ei_sys::ei_decode_ref(self.xbuf.buff, &mut self.xbuf.index, val.as_mut_ptr())
                };
                if erl_code == ei_sys::ERL_ERROR {
                    Err(ErlangTypeError::DecodeFails)
                } else {
                    Ok(ErlangRef(unsafe {val.assume_init()}))
                }
            } else {
                Err(ErlangTypeError::TypeDiffers)
            }
        })
    }

    pub fn skip_term(&mut self) -> &mut XBuf {
        unsafe {
            ei_sys::ei_skip_term(self.xbuf.buff, &mut self.xbuf.index)
        };
        self
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

fn cstr2ruststr(input: &[i8]) -> String {
    let cstr = unsafe {
        std::ffi::CStr::from_ptr(input.as_ptr())
    };
    let cstring = std::ffi::CString::from(cstr);
    cstring.to_str().and_then(
        |s|Ok(String::from(s))
    ).unwrap()
}