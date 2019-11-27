extern crate ei_sys;

mod ei;

fn main() {
    let port = 20170;
    let mut cnode: ei::ErlangNode = ei::init().and_then(init_cnode).expect("can not create cnode!");
    let _epmd_fd = cnode.publish(port).expect("can not publish port to epmd");
    let (listen_fd, _) = cnode.listen(Some(port), 10).expect("can not listen on port");

    loop {
        if let Ok(_conn) = cnode.accept(listen_fd) {
            println!("got connection!")
        }
    }
}


fn init_cnode(_ignore: ()) -> Result<ei::ErlangNode, i32> {
    ei::NodeBuilder::new("secret", "cnode").connect_init()
}