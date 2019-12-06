mod ei;


fn main() {
    let port = 20170;
    let mut cnode: ei::ErlangNode = ei::init().and_then(init_cnode).expect("can not create cnode!");
    let _epmd_fd = cnode.publish(port).expect("can not publish port to epmd");
    let (listen_fd, _) = cnode.listen(Some(port), 10).expect("can not listen on port");


    loop {
        println!("waiting for connection");
        let _ = cnode.accept(listen_fd)
                .and_then(handle_connection);

    }
}

fn handle_connection((fd, _): (i32, ei::ErlConnect)) -> Result<(), i32> {
    let mut run = 1;
    while run == 1 {
        let mut xbuf = ei::XBuf::new();
        let recvd = xbuf.receive_msg(fd);
        if recvd.is_err() {
            continue
        }
        let msg:ei::ErlangMsg = recvd.unwrap();
        xbuf.reset_index();
        xbuf.decode_version();
        match msg.get_type(){
            ei::ErlangMsgType::Send | ei::ErlangMsgType::RegSend => println!("got message of type {:?}", msg.get_type()),
            _ => println!("got something unexpected"),
        }
        match xbuf.get_type().unwrap() {
            ei::ErlangType::Atom(_) => {
                let atom = xbuf.decode_atom().unwrap();
                println!("got atom: {:?}", atom);
                if atom == "quit" {
                    run = 0;
                }
            },
            ei::ErlangType::Binary(_) => {
                let binary = xbuf.decode_binary().unwrap();
                println!("got binary: {:?}", binary);
            }
            _ => println!("got unimplemented type!")

        };
    }
    ei::close_connection(fd);
    Ok(())
}


fn init_cnode(_ignore: ()) -> Result<ei::ErlangNode, i32> {
    ei::NodeBuilder::new("secret", "cnode").connect_init()
}