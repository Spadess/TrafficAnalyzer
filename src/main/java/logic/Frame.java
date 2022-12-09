package logic;
import logic.Headers.*;
public class Frame{
    private Ethernet ethernet;
    private IPv4 ipv4;
    private TCP tcp;
    private HTTP http;
    private final int FrameNo;
    private static int cpt = 0;
    private int ipv4hlen, tcphlen, FlowNo;
    private String rawhex, srcip, srcport, protocol, destip, destport,size, Error;


    public Frame(String rawhex, Ethernet ethernet, IPv4 ipv4, TCP tcp, HTTP http) {
        cpt++;
        Error = "";
        this.rawhex = rawhex;
        this.FrameNo = cpt;
        this.size = String.valueOf(Reader.CountBytes(rawhex));
        this.ethernet = ethernet;
        this.ipv4 = ipv4;
        this.tcp = tcp;
        this.http = http;
        if(ethernet != null){
            this.protocol = "Ethernet";
            if (ipv4 != null) {
                this.srcip = ipv4.getSourceIP();
                this.destip = ipv4.getDestIP();
                this.ipv4hlen = ipv4.getHeaderLength();
                this.protocol = "IPv4";
                if (tcp != null) {
                    this.tcphlen = tcp.getHeaderLength();
                    tcp.getFlagDetails();
                    this.protocol = "TCP"; //+ tcp.getActiveFlags();
                    this.srcport = String.valueOf(tcp.getSourcePort());
                    this.destport = String.valueOf(tcp.getDestPort());
                    if (http != null) this.protocol = "HTTP"; //+ http.getHttpMethod();
                }
            }
        }
    }

    public Ethernet getEthernet() {
        return ethernet;
    }

    public void setFlowNo(int FlowNo) {
        this.FlowNo = FlowNo;
    }

    public int getFlowNo() {
        return FlowNo;
    }

    public IPv4 getIpv4() {
        return ipv4;
    }

    public TCP getTcp() {
        return tcp;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public HTTP getHttp() {
        return http;
    }

    public void setError(String error) {
        Error = error;
    }

    public String getError(){
        return this.Error;
    }

    public static void resetCpt(){
        cpt = 0;
    }

    public int getFrameNo(){
        return this.FrameNo;
    }

    public int getIpv4hlen(){return this.ipv4hlen;}

    public int getTcphlen(){return this.tcphlen;}

    public String getProtocol(){
        return this.protocol;
    }


    public String getRawhex() {
        if(ethernet==null && ipv4==null && tcp==null && http==null) return "";
        StringBuilder sb = new StringBuilder(rawhex);
        for(int i=47;i<rawhex.length();i+=48){
            sb.replace(i,i+1, "\n");
        }
        return sb.toString();
    }

    public String getSrcip() {
        if(ipv4==null) return "";
        return ipv4.getSourceIP();
    }

    public String getSrcport() {
        if(tcp==null) return "";
        return String.valueOf(tcp.getSourcePort());
    }

    public String getDestip() {
        if(ipv4==null) return "";
        return ipv4.getDestIP();
    }

    public String getDestport() {
        if(tcp==null) return "";
        return String.valueOf(tcp.getDestPort());
    }

    public String getSize(){
        if(ethernet==null && ipv4==null && tcp==null && http==null) return "";
        return this.size;
    }
}