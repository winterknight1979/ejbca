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
package org.ejbca.util;

import com.novell.ldap.LDAPException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import org.apache.log4j.Logger;

/**
 * @author johan
 * @version $Id: TCPTool.java 22117 2015-10-29 10:53:42Z mikekushner $
 */
public final class TCPTool {
    private TCPTool() { }
    /** Logger. */
  private static final Logger LOG = Logger.getLogger(TCPTool.class);

  /**
   * Probe a TCP port connection at hostname:port.
   *
   * @param hostname Host
   * @param port Port
   * @param timeout in milliseconds
   * @throws LDAPException if the connection fails
   */
  public static void probeConnectionLDAP(
      final String hostname, final int port, final int timeout)
      throws LDAPException {
    try {
      probeConnectionRaw(hostname, port, timeout);
    } catch (IOException e) {
      String msg = "Unable to connect to " + hostname + ":" + port + ".";
      throw new LDAPException(msg, LDAPException.CONNECT_ERROR, msg);
    }
  }

  /**
   * Probe a TCP port connection at hostname:port.
   *
   * @param hostname Host
   * @param port Port
   * @param timeout in milliseconds
   * @throws IOException if the connection fails
   */
  private static void probeConnectionRaw(
      final String hostname, final int port, final int timeout)
      throws IOException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">probeConnectionRaw("
              + hostname
              + ", "
              + port
              + ", "
              + timeout
              + ")");
    }
    Socket probeSocket = new Socket();
    probeSocket.connect(new InetSocketAddress(hostname, port), timeout);
    probeSocket.close();
    if (LOG.isTraceEnabled()) {
      LOG.trace("<probeConnectionRaw");
    }
  }
}
