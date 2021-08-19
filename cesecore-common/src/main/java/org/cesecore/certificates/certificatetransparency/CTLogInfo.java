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
package org.cesecore.certificates.certificatetransparency;

import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Random;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.keys.util.KeyUtil;

/**
 * Represents a Certificate Transparency log.
 *
 * @version $Id: CTLogInfo.java 27471 2017-12-07 15:13:58Z bastianf $
 */
public final class CTLogInfo implements Serializable {

  /** Logger. */
  private static final Logger LOG = Logger.getLogger(CTLogInfo.class);
  private static final long serialVersionUID = 1L;

  /** ID. */
  private final int logId;
  /** PK. */
  private byte[] publicKeyBytes;
  /** URL. */
  private String url; // base URL, without "add-chain" or "add-pre-chain"
  /** Timeout. */
  private int timeout = 5000; // milliseconds
  /** Label. */
  private String label;
  /** Mandatory. */
  @Deprecated private boolean isMandatory;
  /** Expiry. */
  private Integer expirationYearRequired;

  /** PK. */
  private transient PublicKey publicKey;
  /** Random generator. */
  private static final Random RANDOM = new Random();

  /**
   * Creates a CT log info object, but does not parse the public key yet (so it
   * can be created from static blocks etc).
   *
   * @param aUrl Base URL to the log. The CT log library will automatically
   *     append the strings "add-chain" or "add-pre-chain" depending on whether
   *     EJBCA is submitting a pre-certificate or a regular certificate.
   * @param aPublicKeyBytes The ASN1 encoded public key of the log.
   * @param aLabel to place CT log under.
   * @param aTimeout of SCT response in ms.
   */
  public CTLogInfo(
      final String aUrl,
      final byte[] aPublicKeyBytes,
      final String aLabel,
      final int aTimeout) {
    if (!aUrl.endsWith("/")) {
      LOG.error(
          "CT Log URL must end with a slash. URL: "
              + aUrl); // EJBCA 6.4 didn't enforce this due to a regression
    }
    if (!aUrl.endsWith("/ct/v1/")) {
      LOG.warn("CT Log URL should end with /ct/v1/. URL: " + aUrl);
    }
    this.logId = RANDOM.nextInt();
    this.url = aUrl;
    if (aPublicKeyBytes == null) {
      throw new IllegalArgumentException("publicKeyBytes is null");
    }
    this.publicKeyBytes = aPublicKeyBytes.clone();
    if (aLabel != null && aLabel.isEmpty()) {
      this.label = "Unlabeled";
    } else {
      this.label = aLabel;
    }
    this.timeout = aTimeout;
  }

  private void ensureParsed() {
    if (publicKey == null) {
      publicKey = KeyUtil.getPublicKeyFromBytes(publicKeyBytes);
      if (publicKey == null) {
        throw new IllegalStateException("Failed to parse key");
      }
    }
  }

  /** @return Internal Id consisting of the hashcode of the URL */
  public int getLogId() {
    return logId;
  }

  /**
   * @return PK
   */
  public PublicKey getLogPublicKey() {
    ensureParsed();
    return publicKey;
  }

  /**
   * @return PK
   */
  public byte[] getPublicKeyBytes() {
    return publicKeyBytes;
  }

  /**
   * @param aPublicKeyBytes PK
   */
  public void setLogPublicKey(final byte[] aPublicKeyBytes) {
    this.publicKey = null;
    this.publicKeyBytes = aPublicKeyBytes;
  }

  /** @return Log Key ID as specified by the RFC, in human-readable format */
  public String getLogKeyIdString() {
    try {
      ensureParsed();
      final MessageDigest md = MessageDigest.getInstance("SHA256");
      final byte[] keyId = md.digest(publicKey.getEncoded());
      return Base64.toBase64String(keyId);
    } catch (NoSuchAlgorithmException e) {
      // Should not happen, but not critical.
      return "";
    } catch (Exception e) {
      return e.getLocalizedMessage();
    }
  }

  /**
   * @return URL
   */
  public String getUrl() {
    return url;
  }

  /**
   * @param aUrl URL
   */
  public void setUrl(final String aUrl) {
    this.url = aUrl;
  }

  /**
   * @return timeout
   */
  public int getTimeout() {
    return timeout;
  }

  /**
   * Determine whether this certificate transparency log belongs to the group of
   * certificate transparency logs to which it is mandatory to publish.
   *
   * @return true if this is a mandatory log, or false otherwise
   */
  public boolean isMandatory() {
    return isMandatory;
  }

  /**
   * Sets the timeout in milliseconds when sending a request to the log server.
   *
   * @param aTimeout timeout
   */
  public void setTimeout(final int aTimeout) {
    if (aTimeout < 0) {
      throw new IllegalArgumentException("Timeout value is negative");
    }
    this.timeout = aTimeout;
  }

  /**
   * Makes sure that a URL ends with /ct/v1/.
   *
   * @param urlToFix URL
   * @return fixed URL
   */
  public static String fixUrl(final String urlToFix) {
    String url = urlToFix.endsWith("/") ? urlToFix : urlToFix + "/";
    if (!url.endsWith("/ct/v1/")) {
      if (!url.endsWith("/ct/")) {
        url = url + "ct/v1/";
      } else {
        url = url + "v1/";
      }
    }
    return url;
  }

  /**
   * @return label
   */
  public String getLabel() {
    return label == null ? "Unlabeled" : label;
  }

  /**
   * @param aLabel label
   */
  public void setLabel(final String aLabel) {
    this.label = aLabel;
  }

  /**
   * Returns the expiration year which certificates published to this CT log
   * must have in order to be accepted, or null if there is no such requirement.
   * For example, if this method returns "2019" then you should only try to
   * publish certificates to this CT log expiring in 2019, since all other
   * certificates will be rejected.
   *
   * @return the expiration year required for all certificates being published
   *     to this log or null if there is no such requirement
   */
  public Integer getExpirationYearRequired() {
    return expirationYearRequired;
  }

  /**
   * Returns the expiration year which certificates published to this CT log
   * must have in order to be accepted, or null if there is no such requirement.
   * See {@link #getExpirationYearRequired()}.
   *
   * @param aExpirationYearRequired the expiration year required for new
   *     certificates being published to this CT log, or null if no such
   *     requirement
   */
  public void setExpirationYearRequired(final Integer aExpirationYearRequired) {
    this.expirationYearRequired = aExpirationYearRequired;
  }

  @Override
  public boolean equals(final Object o) {
    if (o == null || o.getClass() != CTLogInfo.class) {
      return false;
    }

    final CTLogInfo ctLogInfo = (CTLogInfo) o;
    return logId == ctLogInfo.getLogId() && url.equals(ctLogInfo.getUrl());
  }

  @Override
  public int hashCode() {
    return logId + (url.hashCode() * 4711);
  }

  @Override
  public String toString() {
    return getUrl();
  }
}
