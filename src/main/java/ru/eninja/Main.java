package ru.eninja;

public class Main {

    /**
     * for filter please google "pcap-filter"
     *
     * @param args 1st is host addr, 2nd is filter (optionally). examples:
     *             192.168.0.26 "udp proto"
     *             192.168.0.26 "portrange 6000-6008"
     *             192.168.0.5
     */
    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Syntax: interceptor hostname [filter]");
            return;
        }

        Interceptor interceptor = new Interceptor(args[0]);

        String filter = args.length == 2 ? args[1] : "";
        interceptor.intercept(filter);
    }
}
