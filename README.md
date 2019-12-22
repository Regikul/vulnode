# vulnode

like a cnode in Erlang, but a node with Vulkan API

## build

    cargo build

## run

start an Erlang node
```
$ erl -sname shell -setcookie secret -remshell "cnode@desktop"
```
Make a connection from Erlang to vulknode
```
(shell@desktop)1> {'cnode', 'cnode@desktop'} ! hello.   
hello
(shell@desktop)2> nodes([hidden]).                                
['cnode@desktop']
(shell@desktop)3> {'cnode', 'cnode@desktop'} ! disconnect.
disconnect
(shell@desktop)4> nodes([hidden]).                                
[]
(shell@desktop)5> {'cnode', 'cnode@desktop'} ! hello.     
hello
(shell@desktop)6> nodes([hidden]).                                
['cnode@desktop']
(shell@desktop)7> {'cnode', 'cnode@desktop'} ! shutdown.  
shutdown
(shell@desktop)8> nodes([hidden]).                              
[]
```
