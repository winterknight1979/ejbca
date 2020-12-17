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

package org.ejbca.ui.web.pub;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.util.HTMLTools;

/**
 * Prints debug info back to browser client.
 *
 * @version $Id: ServletDebug.java 34105 2019-12-18 08:59:00Z undulf $
 */
public class ServletDebug {
      /** Param. */
  private final ByteArrayOutputStream buffer;
  /** Param. */
  private final PrintStream printer;
  /** Param. */
  private final HttpServletRequest request;
  /** Param. */
  private final HttpServletResponse response;

  /**
   * @param arequest req
   * @param aresponse Resp
   */
  public ServletDebug(
      final HttpServletRequest arequest, final HttpServletResponse aresponse) {
    buffer = new ByteArrayOutputStream();
    printer = new PrintStream(buffer);
    this.request = arequest;
    this.response = aresponse;
  }

  /**
   * Empties the buffer to the page.
   *
   * @throws IOException fail
   * @throws ServletException fail
   */
  public void printDebugInfo() throws IOException, ServletException {
    final int len = 7;
    String errorform = request.getParameter("errorform");
    String errormessage = new String(buffer.toByteArray());
    if (errorform == null) {
      request.setAttribute("ErrorMessage", errormessage);
      request.getRequestDispatcher("error.jsp").forward(request, response);
    } else {
      errorform = HTMLTools.htmlescape(errorform);
      int i = errorform.indexOf("@ERROR@");
      if (i > 0) {
        errorform =
            errorform.substring(0, i)
                + errormessage
                + errorform.substring(i + len);
      }
      response.setContentType("text/html;charset=UTF-8");
      response.getOutputStream().print(errorform);
    }
  }

  /**
   * @param o object
   */
  public void print(final Object o) {
    printer.println(o);
  }

  /**
   * @param omsg message
   */
  public void printMessage(final String omsg) {
    // Format message
    String msg = omsg;
    final int len = 150;
    while (msg.length() > len) {
      int offset = msg.substring(0, len).lastIndexOf(' ');
      print(msg.substring(0, offset));
      msg = msg.substring(offset + 1);
    }
    print(msg);
  }

  /**
   * @param bA Byte array
   */
  public void printInsertLineBreaks(final byte[] bA) {
    BufferedReader br =
        new BufferedReader(new InputStreamReader(new ByteArrayInputStream(bA)));
    while (true) {
      String line;
      try {
        line = br.readLine();
      } catch (IOException e) {
        throw new IllegalStateException(
            "Unexpected IOException was caught.", e);
      }
      if (line == null) {
        break;
      }
      print(line.toString());
    }
  }

  /**
   * @param t exception
   */
  public void takeCareOfException(final Throwable t) {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    t.printStackTrace(new PrintStream(baos));
    print("Exception:");

    try {
      printInsertLineBreaks(baos.toByteArray());
    } catch (Exception e) {
      e.printStackTrace(printer);
    }

    request.setAttribute("Exception", "true");
  }

  /**
   * @param bA Byte array
   * @throws Exception Fail
   */
  public void ieCertFix(final byte[] bA) throws Exception {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    PrintStream tmpPrinter = new PrintStream(baos);
    RequestHelper.ieCertFormat(bA, tmpPrinter);
    printInsertLineBreaks(baos.toByteArray());
  }
}
 // Debug
