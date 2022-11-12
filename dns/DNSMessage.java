package dns;

import java.net.DatagramPacket;
import java.util.HashMap;
import java.util.Arrays;

// Class representing a single DNS message.
public class DNSMessage {
    // Declare global variables
    private DatagramPacket in_packet;
    private HashMap<String,Object> headerFields;

    // Constructor
    public DNSMessage(DatagramPacket in_packet) {
        this.in_packet = in_packet;
        parseInput(in_packet);
        toString();
    }

    private void parseInput(DatagramPacket in_packet) {
        byte[] DNSData = in_packet.getData();
        headerFields = new HashMap<String,Object>();

        int[] DNSarray = new int[6];
        int j = 0; 
        for (int i = 0; i< 2*6; i += 2) {
            DNSarray[j] = byteToInt(DNSData[i], DNSData[i+1]);
            j++;
        }
       
        // HashMap the 6 fields
        headerFields.put("ID", DNSarray[0]);
        headerFields.put("FLAGS", DNSarray[1]);
        headerFields.put("QUESTIONS", DNSarray[2]);
        headerFields.put("ANSWERS", DNSarray[3]);
        headerFields.put("AUTHORITY", DNSarray[4]);
        headerFields.put("ADDTIONAL", DNSarray[5]);

        parseFlags();
        parseQuestions(DNSData);
    }

    // Convert 2 bytes into a 16 bit integer
    private int byteToInt(byte byte1, byte byte2) {
        int converted = ((byte1 & 0xff)<<8) | ((byte2 & 0xff));
        return converted;
    }

    // Parse the Flags field into 3 subfields
    private void parseFlags() {
        int flags = (int)headerFields.get("FLAGS");
        headerFields.put("QR", getBits(flags, 1, 16));
        headerFields.put("OPCODE", getBits(flags, 4, 12));
        headerFields.put("RD", getBits(flags, 1, 9));
    }

    // Get n bits starting at position k (from the right side)
    private int getBits(int flags, int numberOfBits, int position) {
        int bits = (((1 << numberOfBits) - 1) & (flags >> (position - 1)));
        return bits;
    }
    
    // Parse the Question field into 3 subfields
    private void parseQuestions(byte[] DNSData) {
        String name = "";
        int h = 0;
        for (int i = 2*6; i < DNSData.length; i++) {
            // Convert all bytes to char until reaching 00 len octet
            char charData = (char) DNSData[i];
            if (DNSData[i] == 0) {
                h = i +1;
                break;
            } else if (Character.isLetter(charData)) {
                name += charData;
            } else if (!name.isEmpty() && !Character.isLetter(charData)) {
                name += ".";
            } 
        }
        headerFields.put("NAME", name);
       
        // Store Question Type and Question Class
        int[] qArray = new int[2];
        int k = 0;
        for (int j = h; j < h + 4; j+=2) {
            qArray[k] = byteToInt(DNSData[j], DNSData[j+1]);
            k++;
        }
        headerFields.put("TYPE", qArray[0]);
        headerFields.put("CLASS", qArray[1]);
    }

    // Print the DNS Message Information on the Server Side
    public String toString() {
        String idStr = "ID: " + String.format("0x%04X", headerFields.get("ID"));
        String flagStr = "\nFLAGS: " + String.format("0x%04X", headerFields.get("FLAGS"));
        String query = getFlagFields(1);
        String request = getFlagFields(2);
        String numQuestions = "\n# Questions: " + headerFields.get("QUESTIONS");
        String answers = "\n# Answers: " + headerFields.get("ANSWERS");
        String authority = "\n# Authority RRs: " + headerFields.get("AUTHORITY"); 
        String additional  = "\n# Additional RRs: " + headerFields.get("ADDTIONAL"); 
        String quest = "\nQuestions: ";
        String questionsFormat = "\n- " + headerFields.get("NAME") + ", " + getQuestionFields();

        String result = idStr + flagStr + query + request + numQuestions + answers + authority + additional + quest + questionsFormat;
        return result;
    }

    // Get Flag Fields Depending on the Bit Value
    private String getFlagFields(int option) {
        String flagString = "\n- "; 
        if (option == 1) {
            if ((int)headerFields.get("QR") == 0) {
                if ((int)headerFields.get("OPCODE") == 0) {
                    flagString += "Standard Query";
                } else {
                    flagString += "Iverse Query or Server Status Request";
                }
            } else {
                flagString += "Reply";
            }
        }

        if (option == 2) {
            if ((int)headerFields.get("RD") == 1) {
                flagString += "Recursion Requested";
            } else {
                flagString += "Recursion Not Requested";
            }
        }
        return flagString; 
    }

    // Get Question Type depending on the Bit Value
    private String getType(int value) {
        String type = "";
        switch(value) {
            case 1: 
                type = "A"; break;
            case 2: 
                type = "NS"; break; 
            case 5: 
                type = "CNAME"; break; 
            case 6: 
                type = "SOA"; break; 
            case 12: 
                type = "PTR"; break; 
            case 28: 
                type = "AAA"; break;
            default: 
                type = Integer.toString(value); 
        }
        return type;
    }

    // Get Question Class depending on the Bit Value
    private String getClass(int value) {
        if (value == 1) { return "IN"; }
        else { return Integer.toString(value); }
    }

    // Return Question Type and Question Class as a String
    private String getQuestionFields() {
        if ((int)headerFields.get("QUESTIONS") == 0) {
            return "ERROR: No Questions!";
        } else {
            String type = getType((int)headerFields.get("TYPE"));
            String classs = getClass((int)headerFields.get("CLASS"));
            String questionsFormat = type + ", " + classs;
            return questionsFormat;
        }
    }
}
