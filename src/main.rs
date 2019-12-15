mod ei;

use std::io::Result as IOResult;
use std::sync::mpsc::{Sender, Receiver, TryRecvError, TrySendError, channel};
use std::collections::HashMap;
use std::thread;

enum InterProcMessage {
    Shutdown,
    Ping,
    Pong,
    NewConnection(ei::ErlangConnection),
}

type Registry<M> = HashMap<String, (Receiver<M>, Sender<M>)>;

fn main() {

    let mut registry:Registry<InterProcMessage> = HashMap::new();

    let (local_sender, remote_recver) = channel::<InterProcMessage>();
    let (remote_sender, local_recver) = channel::<InterProcMessage>();

    registry.insert(String::from("net_accepter"), (local_recver, local_sender));

    let _ = thread::spawn(move || {
        connection_accepter(remote_recver, remote_sender, ())
    });

    let mut shutdown = false;

    while !shutdown {
        registry.retain(|child_name, (rx, tx)| {

             match rx.try_recv() {
                 Ok(InterProcMessage::Shutdown) => {
                     println!("going in shutdown state");
                     shutdown = true;
                 },
                 Ok(InterProcMessage::NewConnection(conn)) => {
                     println!("got connection request from {}", conn.remote_node)
                 },
                 Ok(InterProcMessage::Ping) => {
                     println!("someone want to know if we are alive! replying");
                     let _ = tx.send(InterProcMessage::Pong);
                 },
                 Ok(InterProcMessage::Pong) => println!("got Pong from {}", child_name),
                 Err(TryRecvError::Empty) => (),
                 Err(TryRecvError::Disconnected) => {
                     println!("{} disconnected", child_name);
                     return false
                 },
             };

            true
        });
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

fn connection_accepter(inbox: Receiver<InterProcMessage>, outbox: Sender<InterProcMessage>, _state: ()) -> () {
    let mut cnode: ei::ErlangNode = ei::init().and_then(init_cnode).expect("can not create cnode!");
    cnode.listen(None, 10).expect("can not listen on port");
    cnode.publish(None).expect("can not publish port to epmd");

    println!("waiting for connection");

    loop {
        if let Ok(connection) = cnode.accept(None) {
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


fn init_cnode(_ignore: ()) -> IOResult<ei::ErlangNode> {
    ei::NodeBuilder::new("secret", "cnode").connect_init()
}