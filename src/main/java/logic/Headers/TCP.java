package logic.Headers;

import logic.Reader;
import java.util.HashMap;


public class TCP {

    private final String header;
    private boolean[] ActiveFlags;
    private final int SourcePort;
    private final int DestPort;
    private final Long SequenceNumber;
    private final Long AcknowledgementNumber;
    private final int HeaderLength;
    private final String Flags;
    private final int Window;
    private final String Checksum;
    private final int UrgentPointer;
    private HashMap<Integer, String> options = new HashMap<>();
    private long CalculatedWindow = -1, TSval = -1,TSecr = -1;
    private int MSS = -1; private boolean SACK = false;

    public TCP(String header) throws Exception{
        int ByteCount = Reader.CountBytes(header);
        if (ByteCount < 20) throw new Exception("Not enough bytes for TCP header"); //check without options
        this.header = header; String s;
        ActiveFlags = new boolean[]{false, false, false, false, false, false};
        options.put(0,"End of Option List"); options.put(4,"Selective Acknowledgement permitted");
        options.put(1,"No Operation"); options.put(5,"Selective ACKnowledgement");
        options.put(2,"Maximum segment size"); options.put(8,"Timestamp and echo of previous timestamp");
        options.put(3,"Window scale");
        //Source & Dest Ports
        SourcePort = Integer.parseInt(Reader.TrimBytes(header,0,2).replaceAll(" ", ""),16);
        DestPort = Integer.parseInt(Reader.TrimBytes(header,2,2).replaceAll(" ", ""),16);
        //Seq & Ack numbers
        SequenceNumber = Long.parseLong(Reader.TrimBytes(header,4,4).replaceAll(" ",""),16);
        AcknowledgementNumber = Long.parseLong(Reader.TrimBytes(header,8,4).replaceAll(" ",""),16);
        //Header Length
        s = Reader.hex2bin(Reader.TrimBytes(header,12,1));
        HeaderLength = Integer.parseInt(s.substring(0,4),2) * 4;
        //System.out.println(ByteCount+" vs "+ipv4hlen+" vs "+HeaderLength);
        if (ByteCount < HeaderLength) throw new Exception("Not enough bytes for TCP header"); //check with options
        //Flags
        Flags = "0x"+Reader.TrimBytes(header, 13, 1);
        //Window
        Window = Integer.parseInt(Reader.TrimBytes(header,14,2).replaceAll(" ",""),16);
        //Checksum
        Checksum = "0x"+Reader.TrimBytes(header,16,2).replaceAll(" ", "");
        //Urgent Pointer
        UrgentPointer = Integer.parseInt(Reader.TrimBytes(header,18,2).replaceAll(" ",""),16);
    }

    public int getSourcePort() {
        return SourcePort;
    }

    public int getDestPort() {
        return DestPort;
    }

    public void checkPorts() throws Exception{
        if(getSourcePort()!=80 && getDestPort()!=80) throw new Exception("non-HTTP Protocol");
    }

    public long getCalculatedWindow() {
        return CalculatedWindow;
    }

    public int getMSS() {return MSS;}

    public boolean check_SACK() {return SACK;}

    public long getTSval(){return  TSval;}

    public long getTSecr(){return TSecr;}

    public Long getSequenceNumber(){
        return SequenceNumber;
    }

    public Long getAcknowledgementNumber(){
        return AcknowledgementNumber;
    }

    public int getHeaderLength() {
        return HeaderLength;
    }


    public String getFlags(){
        return Flags;
    }
    public String getFlagDetails(){
        StringBuilder sb = new StringBuilder();
        String flags = Reader.hex2bin(Reader.TrimBytes(header, 13,1));
        String urg = flags.substring(2,3);
        String ack = flags.substring(3,4);
        String psh = flags.substring(4,5);
        String rst = flags.substring(5,6);
        String syn = flags.substring(6,7);
        String fin = flags.substring(7,8);
        sb.append("\tURG: ");
        if (urg.equals("0")) sb.append("Not set");
        else {
            sb.append("Set");
            ActiveFlags[0] = true;
        }
        sb.append("\n\t.ACK: ");
        if (ack.equals("0")) sb.append("Not set");
        else {
            sb.append("Set");
            ActiveFlags[1] = true;
        }
        sb.append("\n\t..PSH: ");
        if (psh.equals("0")) sb.append("Not set");
        else {
            sb.append("Set");
            ActiveFlags[2] = true;
        }
        sb.append("\n\t...RST: ");
        if (rst.equals("0")) sb.append("Not set");
        else {
            sb.append("Set");
            ActiveFlags[3] = true;
        }
        sb.append("\n\t....SYN: ");
        if (syn.equals("0")) sb.append("Not set");
        else {
            sb.append("Set");
            ActiveFlags[4] = true;
        }
        sb.append("\n\t.....FIN: ");
        if (fin.equals("0")) sb.append("Not set");
        else {
            sb.append("Set");
            ActiveFlags[5] = true;
        }

        return sb.toString();
    }

    public String getActiveFlags(){
        if(ActiveFlags[5] && ActiveFlags[1]) return "[FIN,ACK]";
        if(ActiveFlags[4] && ActiveFlags[1]) return "[SYN,ACK]";
        if(ActiveFlags[2] && ActiveFlags[1]) return "[PSH,ACK]";
        if(ActiveFlags[4]) return "[SYN]";
        if(ActiveFlags[1]) return "[ACK]";
        if(ActiveFlags[5]) return "[FIN]";
        if(ActiveFlags[2]) return "[PSH]";
        if(ActiveFlags[0]) return "[URG]";
        if(ActiveFlags[3]) return "[RST]";
        return "";
    }

    public int getWindow(){
        return Window;
    }

    public String getChecksum() {
        return Checksum;
    }
    public int getUrgentPointer(){
        return UrgentPointer;
    }

    public String getOptions(){
        StringBuilder sb = new StringBuilder(); int len;
        int headerlen = getHeaderLength();
        if (headerlen == 20) return "";

        sb.append(">Options: ").append(headerlen - 20).append(" bytes\n");
            int offset = 20;
            while(offset < (headerlen)){
                String Type = Reader.TrimBytes(header, offset, 1);

                switch (Type) {
                    case "00":
                        sb.append("\tTCP Option: ").append(options.get(0)).append("\n");
                        sb.append("\t\tType: ").append(Integer.parseInt(Type, 16)).append("\n");
                        offset++;
                        break;

                    case "01":
                        sb.append("\tTCP Option: ").append(options.get(1)).append("\n");
                        sb.append("\t\tType: ").append(Integer.parseInt(Type, 16)).append("\n");
                        offset++;
                        break;

                    case "02":
                        sb.append("\tTCP Option: ").append(options.get(2)).append("\n");
                        sb.append("\t\tType: ").append(Integer.parseInt(Type, 16)).append("\n");
                        len = Integer.parseInt(Reader.TrimBytes(header, offset + 1, 1), 16);
                        MSS = Integer.parseInt(Reader.TrimBytes(header, offset +2,2).replaceAll(" ",""),16);
                        sb.append("\t\tMSS: ").append(MSS).append(" bytes\n");
                        offset+=len;
                        break;

                    case "03":
                        sb.append("\tTCP Option: ").append(options.get(3)).append("\n");
                        sb.append("\t\tType: ").append(Integer.parseInt(Type, 16)).append("\n");
                        len = Integer.parseInt(Reader.TrimBytes(header, offset + 1, 1), 16);
                        int value = Integer.parseInt(Reader.TrimBytes(header, offset +2,1));
                        sb.append("\t\tValue: ").append(value).append("\n");
                        CalculatedWindow = (long) (getWindow() * Math.pow(2.0, value));
                        sb.append("\t\tCalculated Window Size: ").append(CalculatedWindow).append(" bytes\n");
                        offset+=len;
                        break;

                    case "04":
                        sb.append("\tTCP Option: ").append(options.get(4)).append("\n");
                        sb.append("\t\tType: ").append(Integer.parseInt(Type, 16)).append("\n");
                        len = Integer.parseInt(Reader.TrimBytes(header, offset + 1, 1), 16);
                        sb.append("\t\tLength: ").append(len).append("\n");
                        SACK = true;
                        offset += len;
                        break;

                    case "05":
                        sb.append("\tTCP Option: ").append(options.get(5)).append("\n");
                        sb.append("\t\tType: ").append(Integer.parseInt(Type, 16)).append("\n");
                        len = Integer.parseInt(Reader.TrimBytes(header, offset + 1, 1), 16);
                        sb.append("\t\tLength: ").append(len).append("\n");
                        offset += len;
                        break;

                    case "08":
                        sb.append("\tTCP Option: ").append(options.get(8)).append("\n");
                        sb.append("\t\tType: ").append(Integer.parseInt(Type, 16)).append("\n");
                        len = Integer.parseInt(Reader.TrimBytes(header, offset + 1, 1), 16);
                        sb.append("\t\tLength: ").append(len).append("\n");
                        TSval = Long.parseLong(Reader.TrimBytes(header, offset + 2, (len - 2) / 2).replaceAll(" ", ""), 16);
                        sb.append("\t\tTimestamp value: ").append(TSval).append("\n");
                        TSecr = Long.parseLong(Reader.TrimBytes(header, offset + 6, (len - 2) / 2).replaceAll(" ", ""), 16);
                        sb.append("\t\tTimestamp echo reply: ").append(TSecr).append("\n");
                        offset += len;
                        break;

                    default:
                        if (!options.containsKey(Integer.parseInt(Type, 16))) {
                            sb.append("\tTCP Option not recognized\n\n");
                            return sb.toString();
                        }
                        else{
                            sb.append("\tTCP Option: ").append(options.get(Integer.parseInt(Type, 16))).append("\n");
                            sb.append("\t\tType: ").append(Integer.parseInt(Type, 16)).append("\n");
                            len = Integer.parseInt(Reader.TrimBytes(header, offset + 1, 1), 16);
                            sb.append("\t\tLength: ").append(len).append("\n");
                            sb.append("\t\tValue: ").append(Long.parseLong(Reader.TrimBytes(header, offset + 2, len - 2).replaceAll(" ", ""), 16)).append("\n");
                            offset += len;
                        }
                        break;
                }
            }
        sb.append("\n");
        return sb.toString();
    }

    public int getTcpPayload(){
        String[] bytes = header.split("\\s+");
        return bytes.length - getHeaderLength();
    }


    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
            sb.append(">Source Port: ").append(getSourcePort()).append("\n\n");
            sb.append(">Destination Port: ").append(getDestPort()).append("\n\n");
            sb.append(">Sequence Number: ").append(getSequenceNumber()).append("\n\n");
            sb.append(">Acknowledgement Number: ").append(getAcknowledgementNumber()).append("\n\n");
            sb.append(">Header Length: ").append(getHeaderLength()).append(" bytes (").append(getHeaderLength()/4).append(")\n\n");
            sb.append(">Flags: ").append(getFlags()).append("\n").append(getFlagDetails()).append("\n\n");
            sb.append(">Window: ").append(getWindow()).append(" bytes\n\n");
            sb.append(">Checksum: ").append(getChecksum()).append("\n\n");
            sb.append(">Urgent Pointer: ").append(getUrgentPointer()).append("\n\n");
            sb.append(getOptions());
            sb.append(">TCP Payload: ").append(getTcpPayload()).append(" bytes\n\n");
            return sb.toString();
        }

          /*public String getReserved(){ //pointless cz always 0
        String s = Reader.TrimBytes(header,12,2).replaceAll(" ","");
        s = Reader.hex2bin(s);
        return ("Reserved: " + s.substring(4,10)+"\n");
    }*/
    }
