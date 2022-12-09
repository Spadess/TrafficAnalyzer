package logic.Headers;

import logic.Reader;


public class Ethernet {
    private final String header;
    private final String SourceMac;
    private final String DestMac;
    private final String Type;

    public Ethernet (String header) throws Exception {
        int ByteCount = Reader.CountBytes(header);
        if (ByteCount < 14) throw new Exception("Not enough bytes for Ethernet header");
        this.header = header;
        SourceMac = Reader.TrimBytes(header, 6, 6).replaceAll(" ", ":");
        DestMac = Reader.TrimBytes(header, 0, 6).replaceAll(" ", ":");
        Type = "0x"+Reader.TrimBytes(header, 12,2).replaceAll(" ", "");
    }

    public void checkType() throws Exception{
        if(Type.contains("0806")) throw new Exception("ARP not treated");
        if(Type.contains("86dd")) throw new Exception("IPv6 not treated");
        if(!Type.contains("0800")) throw new Exception("Ethernet Type not recognized");
    }
    public String getType(){
        return Type;
    }


    public String getSourceMac() {
        return  SourceMac;
    }

    public String getDestMac() {
        return DestMac;
    }

    public int getEthernetPayload(){
        String[] bytes = header.split("\\s+");
        return bytes.length - 14;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
            sb.append(">MAC Source Address: ").append(getSourceMac()).append("\n\n");
            sb.append(">MAC Destination Address: ").append(getDestMac()).append("\n\n");
            sb.append(">Type: ").append(getType());
            if(Type.contains("0800")) sb.append(" (IPv4)\n\n"); else sb.append("\n\n");
            sb.append(">Header Length: 14 bytes\n\n");
            sb.append(">Ethernet Payload: ").append(getEthernetPayload()).append(" bytes\n\n");
            return sb.toString();
    }

}
