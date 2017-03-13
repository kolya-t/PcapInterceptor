package ru.eninja;

import org.pcap4j.core.*;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.Date;

import static org.pcap4j.core.PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;

public class Interceptor {

    private PcapNetworkInterface nif;
    private PcapHandle handle;

    private long packetCounter;
    private long startTime;
    private SimpleDateFormat dateFormat;

    public Interceptor(String host) {
        try {
            // Find Network Interface
            InetAddress addr = InetAddress.getByName(host);
            nif = Pcaps.getDevByAddress(addr);
            dateFormat = new SimpleDateFormat("mm:ss");
        } catch (UnknownHostException | PcapNativeException e) {
            throw new InterceptorException(e);
        }
    }

    /**
     * @param filter may be {@code null}
     */
    public void intercept(String filter) {
        if (filter == null) {
            filter = "";
        }

        try {
            System.out.println("Wait for packets...");
            // Open Pcap Handle
            handle = nif.openLive(65536, PROMISCUOUS, 0);

            handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);

            // TODO: Loop breaker
//            new Thread(() -> {
//                try {
//                    while (true) {
//                        if (System.in.available() != 0) {
//                            handle.breakLoop();
//                            handle.close();
//                            break;
//                        }
//                    }
//                } catch (NotOpenException | IOException e) {
//                    throw new InterceptorException(e);
//                }
//            }).start();

            // ready for loop
            packetCounter = 0;
            startTime = System.currentTimeMillis();
            printHeader();

            // Loop
            handle.loop(-1, this::printPacketInfo);
        } catch (PcapNativeException | NotOpenException | InterruptedException e) {
            throw new InterceptorException(e);
        }
    }

    private void printHeader() {
        System.out.printf("%-8s %-8s %-15s %-15s %-8s %-6s\n",
                "No.",
                "Time",
                "Source",
                "Destination",
                "Protocol",
                "Length");
    }

    private void printPacketInfo(Packet packet) {
        ++packetCounter;
        Date timeFromStart = new Date(handle.getTimestamp().getTime() - startTime);

        if (!packet.contains(IpPacket.class)) {
            System.out.printf("%8d %-8s %-15s\n",
                    packetCounter,
                    dateFormat.format(timeFromStart),
                    "Not IP packet");
            return;
        }

        IpPacket ipPacket = packet.get(IpPacket.class);
        System.out.printf("%8d %-8s %-15s %-15s %8s %6d\n",
                packetCounter,
                dateFormat.format(timeFromStart),
                ipPacket.getHeader().getSrcAddr().getHostAddress(),
                ipPacket.getHeader().getDstAddr().getHostAddress(),
                ipPacket.getHeader().getProtocol(),
                ipPacket.length());
    }
}
