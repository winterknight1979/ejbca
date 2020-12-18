/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.protocol.ws.client;

import java.io.PrintStream;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import org.ejbca.core.protocol.ws.client.gen.ExtendedInformationWS;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.util.cert.OID;

/**
 * Utility for parsing optional user data from the command arguments.
 *
 * @author Lars Silvén $Id: ParseUserData.java 19902 2014-09-30 14:32:24Z anatom
 *     $
 */
final class ParseUserData {
      /** Type. */
  static final String CERT_SERIAL_NO = "CERTIFICATESERIALNUMBER";
  /** Type. */
  private static final String HEX_PREFIX = "0x";

  private ParseUserData() { }
  /**
   * Updates the user data from optional properties defined by "<key>=<value>"
   * on the command line.
   *
   * @param args input from the command line
   * @param userData data to modify.
   * @param ps stream to print info for the user
   * @return args with optional arguments removed
   */
  static String[] getDataFromArgs(
      final String[] args, final UserDataVOWS userData, final PrintStream ps) {
    final List<ExtendedInformationWS> lei =
        new LinkedList<ExtendedInformationWS>();
    final List<String> lArgs = new LinkedList<String>();
    for (int i = 0; i < args.length; i++) {
      final String arg = args[i];
      final int equalPos = arg.indexOf('=');
      if (equalPos < 0 || equalPos + 1 > arg.length()) {
        lArgs.add(arg);
        continue;
      }
      final String key = arg.substring(0, equalPos).trim();
      final String value = arg.substring(equalPos + 1, arg.length()).trim();
      if (key.equalsIgnoreCase(CERT_SERIAL_NO)) {
        final boolean isHex =
            value.substring(0, HEX_PREFIX.length())
            .equalsIgnoreCase(HEX_PREFIX);
        final BigInteger nr;
        try {
          nr =
              isHex
                  ? new BigInteger(value.substring(HEX_PREFIX.length()), 16)
                  : new BigInteger(value);
        } catch (NumberFormatException e) {
          ps.println(
              CERT_SERIAL_NO
                  + " '"
                  + value
                  + "' is not a valid number");
          System.exit(
              -1); // problem with extension data. User info printed by
                   // ParseUserData.getDataFromArgs
          return null; // this line will never be executed but prevents
                       // compilation error.
        }
        userData.setCertificateSerialNumber(nr);
        continue;
      }
      if (OID.isStartingWithValidOID(key)) {
        lei.add(new ExtendedInformationWS(key, value));
        continue;
      }
      lArgs.add(arg);
    }
    if (lei.size() > 0) {
      userData.setExtendedInformation(lei);
    }
    return lArgs.toArray(new String[lArgs.size()]);
  }
  /**
   * Prints info for the user about the optional user data arguments.
   *
   * @param ps stream to print to.
   */
  static void printCliHelp(final PrintStream ps) {
    ps.println(
        "Certificate serial number and certificate extension may be added as"
            + " extra parameters. These parameters may be inserted at any"
            + " position since they are removed before the other parameters"
            + " (above) are parsed.");
    ps.println(
        "For certificate serial number the parameter looks like this '"
            + CERT_SERIAL_NO
            + "=<serial number>'. Start the number with '"
            + HEX_PREFIX
            + "' to indicated that it is hexadecimal. Example: "
            + CERT_SERIAL_NO
            + "=8642378462375036 "
            + CERT_SERIAL_NO
            + "=0x5a53875acdaf24");
    ps.println(
        "For certificate extension the parameter look like this"
            + " '<oid>[.<type>]=value'. The key '1.2.3.4' is same as"
            + " '1.2.3.4.value'. Example: 1.2.840.113634.100.6.1.1=00aa00bb"
            + " 1.2.3.4.value1=1234 1.2.3.4.value2=abcdef");
  }
}
