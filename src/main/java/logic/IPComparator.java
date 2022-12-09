package logic;
import java.util.Comparator;

public class IPComparator implements Comparator<String> {

    @Override
    public int compare(String o1, String o2) {
        if (o1 == null && o2 == null) return 0;
        if (o1 == null) return -1;
        if (o2 == null) return 1;

        String[] bytes1 = o1.split("\\.");
        String[] bytes2 = o2.split("\\.");

        for(int i=0; i<bytes1.length; i++){
            try{
                if (Integer.parseInt(bytes1[i]) > Integer.parseInt(bytes2[i])) return 1;
                else if (Integer.parseInt(bytes1[i]) < Integer.parseInt(bytes2[i])) return -1;
            } catch(NumberFormatException ignored){}
        }
        return 0;
    }
}