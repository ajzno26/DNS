package dns;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

// Class representing a DNS Server.
public class DNSServer {
    
    // DNS uses port UDP port 53 for the server
    final private int PORT = 53;

    // set the maximum packet size to be 1400 bytes for DNS messages
    final private int MAX_SIZE = 1400;

    // Required constructor that simply prints out a message.
    public DNSServer() {
        System.out.printf("Starting server on port %d%n", PORT);
    }

    // Open a socket to receive UDP packets and handle those packets
    public void run() {
        // open the socket, ensure it will close when the try block finishes
        try (
            // listen on localhost only
            var sock = new DatagramSocket(PORT, InetAddress.getLoopbackAddress());
        ) {
            // keep reading packets one at a time, forever
            while(true) {

                // packet to store the incoming message
                var in_packet = new DatagramPacket(new byte[MAX_SIZE], MAX_SIZE);

                // blocking call, read one packet
                sock.receive(in_packet);

                System.out.println("Request received from " + in_packet.getSocketAddress());

                // create a DNS Message object that will parse the packet data
                var message = new DNSMessage(in_packet);

                // print the message contents
                System.out.println(message);
            }
        } catch(IOException e) {
            // Have to catch IOexceptions for most socket calls
            System.out.println("Network error!");
        }
    }

    // Server starting point
    public static void main(String[] args) {
        // make the server object then start listening for DNS requests
        var server = new DNSServer();
        server.run();
    }
}
