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
package org.ejbca.ui.web;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.fileupload.FileItemIterator;
import org.apache.commons.fileupload.FileItemStream;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.fileupload.util.Streams;
import org.apache.commons.lang.ArrayUtils;

/**
 * Handles file uploads and parameters in forms with a file field (since
 * request.getParameter doesn't work in that case). It also supports returning
 * parameters in the case when there's no file upload control, and parameters
 * can be queried multiple times (unlike in the underlying Apache commons file
 * uploads API).
 *
 * @version $Id: HttpUpload.java 28844 2018-05-04 08:31:02Z samuellb $
 */
public class HttpUpload {

    /**
     * Param.
     */
  private final ParameterMap parameterMap;
  /** Param. */
  private final Map<String, byte[]> fileMap;

  /**
   * Creates a new upload state and receives all file and parameter data. This
   * constructor can only be called once per request.
   *
   * <p>Use getParameterMap() and getFileMap() on the new object to access the
   * data.
   *
   * @param request The servlet request object.
   * @param fileFields The names of the file fields to receive uploaded data
   *     from.
   * @param maxbytes Maximum file size.
   * @throws IOException if there are network problems, etc.
   * @throws FileUploadException if the request is invalid.
   */
  public HttpUpload(
      final HttpServletRequest request,
      final String[] fileFields,
      final int maxbytes)
      throws IOException, FileUploadException {
    if (ServletFileUpload.isMultipartContent(request)) {
      final Map<String, ArrayList<String>> paramTemp = new HashMap<>();
      fileMap = new HashMap<>();

      final ServletFileUpload upload = new ServletFileUpload();
      final FileItemIterator iter = upload.getItemIterator(request);
      while (iter.hasNext()) {
        final FileItemStream item = iter.next();
        final String name = item.getFieldName();
        if (item.isFormField()) {
          ArrayList<String> values = paramTemp.get(name);
          if (values == null) {
            values = new ArrayList<>();
            paramTemp.put(name, values);
          }
          values.add(
              Streams.asString(
                  item.openStream(), request.getCharacterEncoding()));
        } else if (ArrayUtils.contains(fileFields, name)) {
          byte[] data = getFileBytes(item, maxbytes);
          if (data != null && data.length > 0) {
            fileMap.put(name, data);
          }
        }
      }

      // Convert to String,String[] map
      parameterMap = new ParameterMap();
      for (Entry<String, ArrayList<String>> entry : paramTemp.entrySet()) {
        final ArrayList<String> values = entry.getValue();
        final String[] valuesArray = new String[values.size()];
        parameterMap.put(entry.getKey(), values.toArray(valuesArray));
      }
    } else {
      parameterMap = new ParameterMap(request.getParameterMap());
      fileMap = new HashMap<>();
    }
  }

  private static byte[] getFileBytes(
      final FileItemStream item, final int maxbytes) {
    try {
      InputStream is = item.openStream();
      int length = 0;
      byte[] file = new byte[maxbytes];

      while (length < maxbytes) {
        int bytesread = is.read(file, length, maxbytes - length);
        if (bytesread <= 0) {
          break;
        }
        length += bytesread;
      }
      return Arrays.copyOf(file, length);
    } catch (IOException e) {
      return null;
    }
  }

  /**
   * @return Map
   */
  public ParameterMap getParameterMap() {
    return parameterMap;
  }

  /**
   * @return Map
   */
  public Map<String, byte[]> getFileMap() {
    return fileMap;
  }
}
