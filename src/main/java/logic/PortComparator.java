package logic;
import java.util.Comparator;

public class PortComparator implements Comparator<String> {

    @Override
    public int compare(String o1, String o2) {
        if (o1 == null && o2 == null) return 0;
        if (o1 == null) return -1;
        if (o2 == null) return 1;

        try{
            Long l1 = Long.parseLong(o1);
            Long l2 = Long.parseLong(o2);
            if(l1 > l2) return 1;
            else if(l1 < l2) return -1;
            return 0;
        } catch(NumberFormatException ignored){}
        return 0;
    }
}