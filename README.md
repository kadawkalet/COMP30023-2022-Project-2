# COMP30023-2022-Project-2: Multithreaded HTTP Server

A simple HTTP server serving HTTP requests via IPv4 or IPv6 concurrently.

#### Compiling and Usage
1. Compile the sever ```make server```
2. Run the server```./server <protocol number> <port number> <path to content>```
3. The request can be made by using cURL via IPv4: ```curl --http1.0 -v http://127.0.0.1:PORT/PATH```
4. The request can also be made by using cURL via IPv6: ```curl --http1.0 -v http://[::1]:PORT/PATH```

Feel Free to give it a try 💪!

----
