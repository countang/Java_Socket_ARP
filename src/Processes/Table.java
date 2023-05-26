package Processes;

import java.util.HashMap;

public class Table {
    public static HashMap<Character, String> Sym_IP_Table = new HashMap<Character, String>() {{
        put('A', "202.119.64.101");
        put('B', "202.119.64.102");
        put('C', "202.119.64.103");
        put('D', "202.119.65.101");
        put('F', "202.119.65.103");
    }};

    public static HashMap<Character, String> Sym_Mac_Table = new HashMap<Character, String>() {{
        put('A', "11-10-22-ED-87-78");
        put('B', "12-10-22-ED-87-78");
        put('C', "13-10-22-ED-87-78");
        put('D', "14-10-22-ED-87-78");
        put('F', "16-10-22-ED-87-78");
//        put('S', "17-10-22-ED-87-78");
//        put('T', "18-10-22-ED-87-78");
//        put('U', "19-10-22-ED-87-78");
//        put('V', "20-10-22-ED-87-78");
    }};
}
