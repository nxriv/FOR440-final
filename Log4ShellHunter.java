import java.io.*;                                                                                                                                                                                                                           
import java.net.URLDecoder;                                                                                                                                                                                                                 
import java.nio.charset.StandardCharsets;                                                                                                                                                                                                   
import java.util.*;                                                                                                                                                                                                                         
                                                                                                                                                                                                                                            
public class Log4ShellHunter {                                                                                                                                                                                                              
    public static void main(String[] args) {                                                                                                                                                                                                
        String logFile = "/home/user1/log4jhunt/http.log"; // ADJUST TO YOUR PATH!!!                                                                                                                                                                                 
                                                                                                                                                                                                                                            
        // exploitable patterns of interest                                                                                                                                                                                                 
        List<String> patterns = Arrays.asList("jndi:", "ldap:");                                                                                                                                                                            
                                                                                                                                                                                                                                            
        try (BufferedReader br = new BufferedReader(new FileReader(logFile))) {                                                                                                                                                             
            String line;                                                                                                                                                                                                                    
            List<String> headers = null;                                                                                                                                                                                                    
            int lineNumber = 0;                                                                                                                                                                                                             
                                                                                                                                                                                                                                            
            while ((line = br.readLine()) != null) {                                                                                                                                                                                        
                lineNumber++;                                                                                                                                                                                                               
                                                                                                                                                                                                                                            
                // skip metadata                                                                                                                                                                                                            
                if (line.startsWith("#")) {                                                                                                                                                                                                 
                    if (line.startsWith("#fields")) {                                                                                                                                                                                       
                        headers = Arrays.asList(line.substring(8).split("\t"));
                    }                                                                                                                                                                                                                       
                    continue;
                }

                if (headers != null) {
                    String[] fields = line.split("\t");
                    Map<String, String> row = new HashMap<>();
                    for (int i = 0; i < headers.size() && i < fields.length; i++) {
                        row.put(headers.get(i), fields[i]);
                    }

                    String uri = decodeField(row.getOrDefault("uri", ""));
                    String host = decodeField(row.getOrDefault("host", ""));
                    String originIP = row.getOrDefault("id.orig_h"," Unknown");

                    if (containsPattern(uri, patterns) || containsPattern(host, patterns)) {
                        System.out.println("Suspicious Request Detected:");
                        System.out.println(" Line Number: " + lineNumber);
                        System.out.println(" Origin IP: " + originIP);
                        System.out.println(" URI: " + uri);
                        System.out.println(" Host: " + host);
                        System.out.println("-----------------------------");
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static String decodeField(String field) {
        try {
            return URLDecoder.decode(field, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            return field;
        }
    }

    private static boolean containsPattern(String field, List<String> patterns) {
        for (String pattern : patterns) {
            if (field.contains(pattern)) {
                return true;
            }
        }
        return false;
    }
}
