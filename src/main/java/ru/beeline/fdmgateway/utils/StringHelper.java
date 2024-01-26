package ru.beeline.fdmgateway.utils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class StringHelper {
    private static final String urlPattern =
            "https?:\\/\\/(www\\.)?[-a-zA-Z0-9@:%._\\+~;#=]{1,256}\\.[a-zA-Z0-9()]{1,6}([-a-zA-Z0-9()@:%_\\+.~;#?&//=]*)";
    public static String removeBraces(String guid) {
        int start = guid.lastIndexOf('{') + 1;
        int end = guid.lastIndexOf('}');
        return guid.substring(start, end);
    }

    public static String urlNormalizer(String html) {
        if(html==null)
            return null;
        html = html.replace("$inet://https", "https");
        html = html.replace("-http", "http");
        Pattern p = Pattern.compile(urlPattern, Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(html);
        StringBuffer sb = new StringBuffer(html.length());
        while (m.find()) {
            String url = m.group(0);
            int start = m.start();
            if (start < 3 ||
                    (!html.substring(start - 2, start).equals("=\"")
                    && !(html.substring(start - 1, start).equals(">") && html.substring(start, m.end()).contains("</a>"))
                    && !html.substring(start - 3, start).equals("://")
                    && !html.substring(start - 1, start).equals("-")
                    && !html.substring(start - 3, start - 1).equals("=\\"))) {
                m.appendReplacement(sb, "<a href=\"" + url + "\"><font color=\"#0000ff\">" + url + "</font></a>");
            } else {
                m.appendReplacement(sb, url);
            }
        }

        m.appendTail(sb);
        return sb.toString();
    }
}
