package logic.Headers;

import logic.Reader;
import java.util.HashMap;

public class IPv4 {

    private final String header;
    private final int Version;
    private final int HeaderLength;
    private final String ToS;
    private final int TotalLength;
    private final String ID;
    private final String Flags;
    private final int FragmentOffset;
    private final int TTL;
    private final int Protocol;
    private final String Checksum;
    private final String SourceIP;
    private final String DestIP;
    private HashMap<Integer, String> options = new HashMap<>();


    public IPv4 (String header) throws Exception{
        int ByteCount = Reader.CountBytes(header);
        if (ByteCount < 20) throw new Exception("Not enough bytes for IPv4 header"); //check without options
        this.header = header; String s;
        //Options
        options.put(0, "End of Option List"); options.put(68, "Time Stamp"); options.put(144, "IMI Traffic Descriptor");
        options.put(1, "No Operation"); options.put(82, "Traceroute"); options.put(145, "Extended Internet Protocol");
        options.put(2, "Security (defunct)"); options.put(94, "RFC3692-style Experiment"); options.put(147, "Address Extension");
        options.put(7, "Record Route"); options.put(130, "Security (RIPSO)");options.put(148, "Router Alert");
        options.put(10, "Experimental Measurement");options.put(131, "Loose Source Route"); options.put(149, "Selective Directed Broadcast");
        options.put(11, "MTU Probe");options.put(133, "Extended Security (RIPSO)"); options.put(151, "Dynamic Packet State");
        options.put(12, "MTU Reply"); options.put(134, "Commercial IP Security Option"); options.put(152, "Upstream Multicast Packet");
        options.put(15, "ENCODE"); options.put(136, "Stream ID"); options.put(158, "RFC3692-style Experiment");
        options.put(25, "Quick-Start"); options.put(137, "Strict Source Route"); options.put(205, "Experimental Flow Control");
        options.put(30, "RFC3692-style Experiment"); options.put(142, "Experimental Access Control"); options.put(222, "RFC3692-style Experiment");
        //Version & IHL
        s = Reader.hex2bin(Reader.TrimBytes(header,0,1));
        Version = Integer.parseInt(s.substring(0, 4), 2);
        HeaderLength = Integer.parseInt(s.substring(4,8),2) * 4;
        if (ByteCount < HeaderLength) throw new Exception("Not enough bytes for IPv4 header"); //check with options
        //TOS
        ToS = "0x" + Reader.TrimBytes(header, 1, 1);
        //Total Length
        TotalLength = ByteCount;
        //ID
        ID = "0x" + Reader.TrimBytes(header, 4, 2).replaceAll(" ", "");
        //Flags
        Flags = "0x"+Reader.TrimBytes(header, 6, 1);
        //Fragment Offset
        s = Reader.hex2bin(Reader.TrimBytes(header,6,4).replaceAll(" ", ""));
        FragmentOffset = Integer.parseInt(s.substring(3,16),2);
        //TTL
        TTL = Integer.parseInt(Reader.TrimBytes(header,8,1).replaceAll(" ", ""), 16);
        //Protocol
        s = Reader.TrimBytes(header,9,1);
        Protocol = Integer.parseInt(s,16);
        //Checksum
        Checksum = "0x"+ Reader.TrimBytes(header,10,2).replaceAll(" ", "");
        //Source IP
        s = Reader.TrimBytes(header,12,4);
        SourceIP = IP_hex2dec(s);
        //Destination IP
        s = Reader.TrimBytes(header,16,4);
        DestIP = IP_hex2dec(s);
    }

    public void checkProtocol() throws Exception {
        if(Protocol == 17) throw new Exception("UDP not treated");
        if(Protocol == 1) throw new Exception("ICMP not treated");
        if(Protocol!=6) throw new Exception("IPv4 Protocol not recognized");
    }
    public int getVersion() {
        return Version;
    }

    public int getHeaderLength() {
        return  HeaderLength;
    }

    public String getToS() {
        return ToS;
    }

    public int getTotalLength(){
        return TotalLength;
    }

    public String getID() {
        return  ID;
    }
    public String getFlags() {
        return Flags;
    }

    public String getFlagDetails() {
        StringBuilder sb = new StringBuilder();
        String flagsBin = Reader.hex2bin(Reader.TrimBytes(header,6,1));
        String RB = flagsBin.substring(0,1);
        String DF = flagsBin.substring(1,2);
        String MF = flagsBin.substring(2,3);
        sb.append("\t").append("RB: ");
        if (RB.equals("0")) sb.append("Not set");
        else sb.append("Set");
        sb.append("\n\t.DF: ");
        if (DF.equals("0")) sb.append("Not set");
        else sb.append("Set");
        sb.append("\n\t..MF: ");
        if (MF.equals("0")) sb.append("Not set");
        else sb.append("Set");
        return sb.toString();
    }

    public int getFragmentOffset() {
        return FragmentOffset;
    }

    public int getTTL() {
        return TTL;
    }

    public int getProtocol() {
        return Protocol;
    }

    public String getChecksum() {
        return Checksum;
    }

    public String getSourceIP() {
        return SourceIP;
    }

    public String getDestIP() {
        return DestIP;
    }

    public String getOptions() {
        StringBuilder sb = new StringBuilder(); int len;
        int headerlen = getHeaderLength();
        if (headerlen == 20) return "";

        sb.append(">Options: ").append(headerlen - 20).append(" bytes\n");
            int offset = 20;
            while(offset < headerlen){
                String Type = Reader.TrimBytes(header, offset, 1);
                switch (Type) {
                    case "00":
                        sb.append("\tIP Option: ").append(options.get(0)).append("\n");
                        sb.append("\t\tType: ").append(Integer.parseInt(Type, 16)).append("\n");
                        offset++;
                        break;
                    case "01":
                        sb.append("\tIP Option: ").append(options.get(1)).append("\n");
                        sb.append("\t\tType: ").append(Integer.parseInt(Type, 16)).append("\n");
                        offset++;
                        break;

                    case "07":
                        sb.append("\tIP Option: ").append(options.get(7)).append("\n");
                        sb.append("\t\tType: ").append(Integer.parseInt(Type, 16)).append("\n");
                        len = Integer.parseInt(Reader.TrimBytes(header, offset + 1, 1), 16);
                        sb.append("\t\tLength: ").append(len).append("\n");
                        sb.append("\t\tPointer: ").append(Integer.parseInt(Reader.TrimBytes(header, offset +2, 1), 16)).append("\n");
                        offset += 3;
                        for (int i=0;i<((len-3)/4);i++) {
                            String routerIP = IP_hex2dec(Reader.TrimBytes(header, offset, 4));
                            sb.append("\t\t\tRouter ").append(i+1).append(": ").append(routerIP).append("\n");
                            offset+=4;
                        }
                        break;
                    default:
                        if (!options.containsKey(Integer.parseInt(Type, 16))) {
                            sb.append("\tIP Option not recognized\n\n");
                            return sb.toString();
                        }
                        else{
                            sb.append("\tIP Option: ").append(options.get(Integer.parseInt(Type, 16))).append("\n");
                            sb.append("\t\tType: ").append(Integer.parseInt(Type, 16)).append("\n");
                            len = Integer.parseInt(Reader.TrimBytes(header, offset + 1, 1), 16);
                            sb.append("\t\tLength: ").append(len).append("\n");
                            offset += len;
                        }
                        break;
                }
            }
        sb.append("\n");
        return sb.toString();
    }

    public String IP_hex2dec (String IPHex){
        StringBuilder sb = new StringBuilder();
        String[] octets = IPHex.split("\\s+");
        for (String o : octets) {
            sb.append(Integer.parseInt(o, 16)).append(".");
        }
        sb.setLength(sb.length() - 1);
        return sb.toString();
    }

    public int getIpv4Payload(){
        String[] bytes = header.split("\\s+");
        return bytes.length - getHeaderLength();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
            sb.append(">Internet Protocol Version ").append(getVersion()).append("\n\n");
            sb.append(">Header Length: ").append(getHeaderLength()).append(" bytes (").append(getHeaderLength()/4).append(")\n\n");
            sb.append(">Type of Service: ").append(getToS()).append("\n\n");
            sb.append(">Total length: ").append(getTotalLength()).append(" bytes\n\n");
            sb.append(">Identification: ").append(getID()).append(" (").append(Integer.parseInt(getID().substring(2), 16)).append(")\n\n");
            sb.append(">Flags: ").append(getFlags()).append("\n").append(getFlagDetails()).append("\n\n");
            sb.append(">Fragment Offset: ").append(getFragmentOffset()).append("\n\n");
            sb.append(">Time to Live: ").append(getTTL()).append("\n\n");
            sb.append(">Protocol: ").append(getProtocol()); if(getProtocol()==6) sb.append(" (TCP)\n\n"); else sb.append("\n\n");
            sb.append(">Checksum: ").append(getChecksum()).append("\n\n");
            sb.append(">Source IP Address: ").append(getSourceIP()).append("\n\n");
            sb.append(">Destination IP Address: ").append(getDestIP()).append("\n\n");
            sb.append(getOptions());
            sb.append(">IPv4 Payload: ").append(getIpv4Payload()).append(" bytes\n\n");
            return sb.toString();
        }
    }
