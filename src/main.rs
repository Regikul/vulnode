mod ei;

use std::io::Result as IOResult;
use std::sync::mpsc::{Sender, Receiver, TryRecvError, channel};
use std::collections::HashMap;
use std::thread;

enum InterProcMessage {
    Shutdown,
    Ping,
    Pong,
    NewConnection(ei::ErlangConnection),
}

type Registry<M> = HashMap<String, (Receiver<M>, Sender<M>)>;

fn spawn_worker<M, F, S>(registry:&mut Registry<M>, name: String, func: F, data: S) -> () 
where
    S: Send + 'static,
    M: Send + 'static,
    F: Send + FnOnce(Receiver<M>, Sender<M>, S) -> () + 'static,
{
    let (local_sender, remote_recver) = channel::<M>();
    let (remote_sender, local_recver) = channel::<M>();

    registry.insert(String::from(name), (local_recver, local_sender));

    let _ = thread::spawn(move || {
        func(remote_recver, remote_sender, data)
    });
}

fn main() {

    let mut registry:Registry<InterProcMessage> = HashMap::new();

    spawn_worker(&mut registry, String::from("net_accepter"), connection_accepter, ());
    spawn_worker(&mut registry, String::from("vulkan_api"), vk_api, ());

    let mut shutdown = false;

    while !shutdown {
        let mut delete = Vec::new();
        let mut add = Vec::new();
        for (child_name, (rx, tx)) in registry.iter_mut() {

             match rx.try_recv() {
                 Ok(InterProcMessage::Shutdown) => {
                     println!("going in shutdown state");
                     shutdown = true;
                 },
                 Ok(InterProcMessage::NewConnection(conn)) => {
                     println!("got connection request from {}", conn.remote_node);
                     add.push(conn);
                 },
                 Ok(InterProcMessage::Ping) => {
                     println!("someone want to know if we are alive! replying");
                     let _ = tx.send(InterProcMessage::Pong);
                 },
                 Ok(InterProcMessage::Pong) => println!("got Pong from {}", child_name),
                 Err(TryRecvError::Empty) => (),
                 Err(TryRecvError::Disconnected) => {
                     println!("{} disconnected", child_name);
                     delete.push(child_name.clone());
                 },
             };
        }
        for child_name in delete.iter() {
            registry.remove_entry(child_name);
        }
        while add.len() > 0 {
            let conn = add.pop().expect("Ooooops!");

            spawn_worker(&mut registry, conn.remote_node.clone(), handle_connection, conn)
        }
        thread::sleep(std::time::Duration::from_millis(1));
    };

    for (_, tx) in registry.values() {
        let _ = tx.send(InterProcMessage::Shutdown);
    }

    while registry.len() > 0 {
        registry.retain(worker_cleanup::<InterProcMessage>);
        thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn worker_cleanup<T>(child_name: &String, (rx, _): &mut (Receiver<T>, Sender<T>)) -> bool {
    match rx.try_recv() {
        Err(TryRecvError::Empty) => true,
        Err(TryRecvError::Disconnected) => {
            println!("{} done", child_name);
            false
        },
        Ok(_) => true,
    }
}

fn vk_api(inbox: Receiver<InterProcMessage>, outbox: Sender<InterProcMessage>, _state: ()) -> () {
    loop {
        match inbox.try_recv() {
            Ok(InterProcMessage::Shutdown) => break,
            Ok(InterProcMessage::Ping) => {
                let _ = outbox.send(InterProcMessage::Pong);
            },
            Err(TryRecvError::Disconnected) => break,
            _ => (),
        }
    }
}

fn connection_accepter(inbox: Receiver<InterProcMessage>, outbox: Sender<InterProcMessage>, _state: ()) -> () {
    let mut cnode: ei::ErlangNode = ei::init().and_then(init_cnode).expect("can not create cnode!");
    cnode.listen(None, 10).expect("can not listen on port");
    cnode.publish(None).expect("can not publish port to epmd");

    println!("waiting for connection");

    loop {
        if let Ok(connection) = cnode.accept(Some(1)) {
            let _ = outbox.send(InterProcMessage::NewConnection(connection));
        }

        match inbox.try_recv() {
            Ok(InterProcMessage::Shutdown) => break,
            Ok(InterProcMessage::Ping) => {
                let _ = outbox.send(InterProcMessage::Pong);
            },
            Err(TryRecvError::Disconnected) => break,
            _ => (),
        }
    };

    cnode.unpublish();
}

fn handle_connection(inbox: Receiver<InterProcMessage>, outbox: Sender<InterProcMessage>, connection: ei::ErlangConnection) -> () {
    let mut shutdown = false;
    while !shutdown {
        match inbox.try_recv() {
            Ok(InterProcMessage::Ping) => {
                println!("someone want to know if we are alive!");
                let _ = outbox.send(InterProcMessage::Pong);
            },
            Ok(InterProcMessage::Shutdown) => {
                shutdown = true;
            },
            Err(TryRecvError::Empty) => (),
            Err(TryRecvError::Disconnected) => {
                shutdown = true;
            }
            _ => (),
        }
        let mut xbuf = ei::XBuf::new();
        let recvd = xbuf.receive_msg(connection.socket, Some(1));
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
                if atom == "disconnect" {
                    shutdown = true;
                };
                if atom == "shutdown" {
                    let _ = outbox.send(InterProcMessage::Shutdown);
                };
            },
            ei::ErlangType::Binary(_) => {
                let binary = xbuf.decode_binary().unwrap();
                println!("got binary: {:?}", binary);
            }
            _else => println!("got unimplemented type! {:?}", _else)

        };
    }
    ei::close_connection(connection.socket);
}

fn init_cnode(_ignore: ()) -> IOResult<ei::ErlangNode> {
    ei::NodeBuilder::new("secret", "cnode").connect_init()
}