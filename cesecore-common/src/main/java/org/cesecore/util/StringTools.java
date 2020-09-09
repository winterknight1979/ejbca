package org.cesecore.util;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.encoders.DecoderException;

public class StringTools {
	
	 /**
     * Takes input and converts to Base64 on the format "B64:<base64 endoced string>", if the string is not null or empty.
     *
     * @param s String to base64 encode
     * @return Base64 encoded string, or original string if it was null or empty
     */
    public static String putBase64String(final String s) {
    	return putBase64String(s, false);
    }
    
    /**
     * Takes input and converts to Base64 on the format "B64:<base64 endoced string>", if the string is not null or empty.
     *
     * @param s String to base64 encode
     * @param dontEncodeAsciiPrintable if the String is made up of pure ASCII printable characters, we will not B64 encode it
     * @return Base64 encoded string, or original string if it was null or empty
     */
    public static String putBase64String(final String s, boolean dontEncodeAsciiPrintable) {
    	if (StringUtils.isEmpty(s)) {
    		return s;
    	}
    	if (s.startsWith("B64:")) {
    		// Only encode once
    		return s;
    	}
    	if (dontEncodeAsciiPrintable && StringUtils.isAsciiPrintable(s)) {
    		return s;
    	}
    	 // Since we used getBytes(s, "UTF-8") in this method, we must use UTF-8 when doing the reverse in another method
    	return "B64:" + new String(Base64.encode(s.getBytes(StandardCharsets.UTF_8), false));
    }

    /**
     * Takes a string given as input and converts it from Base64 if the string
     * begins with the case-insensitive prefix b64, i.e. is on format "b64:<base64 encoded string>".
     *
     * @param input String to Base64 decode
     * @return Base64 decoded string, or original string if it was not base64 encoded
     */
	public static String getBase64String(final String input) {
		if (StringUtils.isEmpty(input)) {
			return input;
		}
		if (!input.toLowerCase().startsWith("b64:")) {
			return input;
		}
		final String base64Data = input.substring(4);
		if (base64Data.length() == 0) {
			return input;
		}
		try {
			// Since we used getBytes(s, "UTF-8") in the method putBase64String, we must use UTF-8 when doing the reverse
			return new String(Base64.decode(base64Data.getBytes("UTF-8")), "UTF-8");
		} catch (UnsupportedEncodingException | DecoderException e) {
			return input;
		}
	}

	public static String ipOctetsToString(byte[] octets) {
		// TODO Auto-generated method stub
		return null;
	}

	public static byte[] ipStringToOctets(String addr) {
		// TODO Auto-generated method stub
		return null;
	}

}
