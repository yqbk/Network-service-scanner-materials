import pcap






socket.IPPROTO_TCP:'tcp'

def getTCP:




//this is already there in the code:
    printf("   Src port: %d\n", ntohs(tcp->th_sport));
    printf("   Dst port: %d\n", ntohs(tcp->th_dport))

//you add:
    if (tcp->th_flags & TH_ECE){
        printf("   Flag: TH_ECE");
    }
    if (tcp->th_flags & TH_RST){
        printf("   Flag: TH_RST");
    }



if __name__=='__main__':

    if len(sys.argv) < 3:
        print 'usage: sniff.py <interface> <expr>'
        sys.exit(0)

        p = pcap.pcapObject()
        #dev = pcap.lookupdev()
        dev = sys.argv[1]
        net, mask = pcap.lookupnet(dev)
        p.open_live(dev, 1600, 0, 100)
        p.setfilter(string.join(sys.argv[2:],' '), 0, 0)

        try:
            while 1:
                p.dispatch(1, print_packet)

            # the loop method is another way of doing things
            #    p.loop(1, print_packet)

            # as is the next() method
            # p.next() returns a (pktlen, data, timestamp) tuple
            #    apply(print_packet,p.next())
        except KeyboardInterrupt:
            print '%s' % sys.exc_type
            print 'shutting down'
            print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()
