/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import org.apache.log4j.Logger;

/**
 * Helper methods for basic network interactions.
 *
 * @version $Id: NetworkTools.java 18958 2014-05-19 15:04:40Z mikekushner $
 */
public abstract class NetworkTools {
    /** Logger. */
  private static final Logger LOG = Logger.getLogger(NetworkTools.class);

  /**
   * @param cdp CDP
   * @return the URL object of the provided CDP if it is well formed and uses
   *     the HTTP protocol. null otherwise
   */
  public static URL getValidHttpUrl(final String cdp) {
    if (cdp == null) {
      return null;
    }
    final URL url;
    try {
      url = new URL(cdp);
    } catch (MalformedURLException e) {
      return null;
    }
    if (!"http".equalsIgnoreCase(url.getProtocol())) {
      return null;
    }
    return url;
  }

  /**
   * @param url URL
   * @param maxSize max size
   * @return the data found at the provided URL if available and the size is
   *     less the maxSize
   */
  public static byte[] downloadDataFromUrl(final URL url, final int maxSize) {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    final int size = 32768;
    final byte[] data = new byte[size]; // 32KiB at the time
    int downloadedBytes = 0;
    InputStream is = null;
    try {
      is = url.openStream();
      int count;
      while ((count = is.read(data)) != -1) {
        baos.write(data, 0, count);
      }
      downloadedBytes += count;
      if (downloadedBytes > maxSize) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Failed to download data from "
                  + url.toString()
                  + ". Size exceedes "
                  + maxSize
                  + " bytes.");
        }
        return null;
      }
    } catch (IOException e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Failed to download data from " + url.toString(), e);
      }
      return null;
    } finally {
      if (is != null) {
        try {
          is.close();
        } catch (IOException e) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("Failed to download data from " + url.toString(), e);
          }
        }
      }
    }
    return baos.toByteArray();
  }
}
