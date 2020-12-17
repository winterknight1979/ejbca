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

package org.ejbca.util.mail;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import javax.activation.DataHandler;
import javax.activation.FileDataSource;

/**
 * Representation of an email attachment.
 *
 * @version $Id: MailAttachment.java 26387 2017-08-22 14:14:36Z mikekushner $
 */
public class MailAttachment {

    /** Param. */
  private final String filename;
  /** Param. */
  private String fullFilePathName;

  /**
   * @param afullFilePathName path
   */
  public MailAttachment(final String afullFilePathName) {
    this.filename = new File(afullFilePathName).getName();
  }

  /**
   * @param afilename file
   * @param afullFilePathName path
   */
  public MailAttachment(
          final String afilename, final String afullFilePathName) {
    this.filename = afilename;
    this.fullFilePathName = afullFilePathName;
  }

  /**
   * Write's the object to a temporary file that is then attached. TODO: In
   * later versions of JavaMail we can use ByteArrayDataSource directly in
   * getDataHandler instead.
   *
   * @param afilename name
   * @param attachedObject object
   */
  public MailAttachment(final String afilename, final Object attachedObject) {
    this.filename = afilename;
    try {
      byte[] attachmentData;
      if (attachedObject instanceof Certificate) {
        try {
          attachmentData = ((Certificate) attachedObject).getEncoded();
        } catch (CertificateEncodingException e) {
          throw new IllegalStateException(
              "The email attachment type is not supported.", e);
        }
      } else {
        throw new IllegalStateException(
            "The email attachment type is not supported.");
      }
      File file = File.createTempFile("ejbca-mailattachment", ".tmp");
      fullFilePathName = file.getCanonicalPath();
      try (FileOutputStream fos = new FileOutputStream(file);
          DataOutputStream dos = new DataOutputStream(fos); ) {
        dos.write(attachmentData);
      }
    } catch (IOException e) {
      throw new IllegalStateException(
          "The email attachment type is not supported.", e);
    }
  }

  /**
   * @return Name
   */
  public String getName() {
    return filename;
  }

  /**
   * @return Handler
   */
  public DataHandler getDataHandler() {
    if (fullFilePathName != null) {
      return new DataHandler(new FileDataSource(getName()));
    }
    return null;
  }
}
