package logic.Headers;

import logic.Reader;

public class HTTP {
    private final String header;
    private final int httpLen;

    public HTTP(String header) throws Exception {
        int ByteCount = Reader.CountBytes(header);
        if (ByteCount < 16) throw new Exception();
        this.header = header;
        String[] bytes = header.split("\\s+");
        httpLen = bytes.length;
    }

    public String HTTPContent(){
        StringBuilder sb = new StringBuilder();
        String[] octets = header.split("\\s+");
        for(int i = 0;i < octets.length; i++){
            sb.append(Reader.hex2ascii(octets[i]));
            if (Reader.hex2ascii(octets[i]).equals("\n")) sb.append("\n");
        }
        sb.append("\n\n");
        return sb.toString();
    }

    public int getHttpLen(){
        return this.httpLen;
    }

    @Override
    public String toString() {
        return HTTPContent();
    }

    public String getHttpMethod(){
        StringBuilder sb = new StringBuilder();
        String[] octets = header.split("\\s+");
        for(String s: octets){
            sb.append(Reader.hex2ascii(s));
            if(sb.length()!=0){
                if(sb.charAt(sb.length()-1) == '\n') break;
            }
        }
        if(!sb.toString().toLowerCase().contains("http")) return "[Sequel]\n";
        return sb.toString();
    }


}
