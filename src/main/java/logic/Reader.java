package logic;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.HashMap;

public class Reader {
    public static Calendar calendar = new GregorianCalendar();
    public static int hour = calendar.get(Calendar.HOUR_OF_DAY);
    public static int minute = calendar.get(Calendar.MINUTE);
    public static int day = calendar.get(Calendar.DATE);
    public static int month = calendar.get(Calendar.MONTH);
    public static int year = calendar.get(Calendar.YEAR);
    public static int lineIndex;
    public static String TrimBytes(String s, int start, int len) {
        StringBuilder sb = new StringBuilder();
            String[] bytes = s.split("\\s+");
            for (int i = start; i < start + len; i++) {
                sb.append(bytes[i]).append(" ");
            }
            if(sb.length()!=0) sb.setLength(sb.length() - 1);
        return sb.toString();
    }

    public static int CountBytes(String s) {
        if (s.length()==0) return 0;
        String[] octets = s.split("\\s+");
        return octets.length;
    }

    public static ArrayList<String> FrameFilter(String fileName) throws Exception {
        BufferedReader br = null;
        StringBuilder buffer = new StringBuilder();
        String line;
        ArrayList<String> FrameList = new ArrayList<>();
        int byte_count = 0; lineIndex = 0;
        try {
            br = new BufferedReader(new FileReader(fileName));
            while ((line = br.readLine()) != null) {
                lineIndex++;
                if (line.equals("")) continue;
                String[] data = line.trim().split("\\s+");
                if (data[0].equals("0000")) { //it means we have a new frame
                    byte_count = 0;
                    if (lineIndex > 1) { //if its the second+ frame that were trying to create and not the first
                        if(buffer.length()!=0) {
                            buffer.deleteCharAt(buffer.length() - 1); //delete the ' ' appended at the end of the frame
                            FrameList.add(buffer.toString());//and add the frame created before to the list
                        }
                        buffer = new StringBuilder();
                    }
                }
                else if (data[0].length() == 4) {
                    if (HexCheck(data[0])) {
                        if (Integer.parseInt(data[0], 16) != byte_count) {
                            buffer.setLength(0);
                            continue;
                            //throw new Exception("Critical Error: Byte count failed at line " + (lineIndex));
                        }
                    }
                    else continue;
                }
                else continue;

                for (int i = 1; i < data.length; i++) {
                    if (data[i].length() == 2 && HexCheck(data[i])) {
                        byte_count++;
                        buffer.append(data[i].toLowerCase()).append(" ");
                    }
                    if(byte_count%16==0) break;
                }

            } //end while
        } catch (FileNotFoundException e) {
            throw e;
        } catch (IOException io) {
            System.out.println("Error Reading the File");
            io.printStackTrace();
        }
        finally {
            if (br != null) {
                br.close();
            }
        }
        if (buffer.length() > 0) {
            buffer.deleteCharAt(buffer.length() - 1); //delete the last appened ' ' to the frame
            FrameList.add(buffer.toString()); //add the last created frame after exiting the while loop
        }
        if(FrameList.isEmpty()) throw new Exception("Non-valid File");
        return FrameList;
    }

    public static boolean HexCheck(String s) {
        try {
            Long.parseLong(s, 16);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public static String hex2bin(String hex) {
        String binary = "";
        hex = hex.toUpperCase();

        HashMap<Character, String> hashMap = new HashMap<>();

        hashMap.put('0', "0000");
        hashMap.put('1', "0001");
        hashMap.put('2', "0010");
        hashMap.put('3', "0011");
        hashMap.put('4', "0100");
        hashMap.put('5', "0101");
        hashMap.put('6', "0110");
        hashMap.put('7', "0111");
        hashMap.put('8', "1000");
        hashMap.put('9', "1001");
        hashMap.put('A', "1010");
        hashMap.put('B', "1011");
        hashMap.put('C', "1100");
        hashMap.put('D', "1101");
        hashMap.put('E', "1110");
        hashMap.put('F', "1111");

        int i;char ch;
        for (i = 0; i < hex.length(); i++) {
            ch = hex.charAt(i);
            if (hashMap.containsKey(ch))
                binary += hashMap.get(ch);
            else {
                binary = "Invalid Hexadecimal String";
                return binary;
            }
        }
        return binary;
    }

    public static String hex2ascii(String hexStr) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hexStr.length(); i += 2) {
            String str = hexStr.substring(i, i + 2);
            if (str.equals("00")) continue;
            else output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }

    public static String getTime(){
        return String.format("%02d:%02d | %d/%d/%d",hour,minute,day,month+1,year);
    }
}