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

package org.ejbca.core.ejb.ca.store;

import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Serializable;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.List;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.persistence.TypedQuery;
import org.apache.log4j.Logger;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.CertTools;
import org.cesecore.util.SecureXMLDecoder;
import org.cesecore.util.StringUtil;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.FixEndOfBrokenXML;

/**
 * Representation of historical information about the data user to create a
 * certificate.
 *
 * <p>the information is currently used to: - list request history for a user -
 * find issuing User DN (EndEntityInformation) when republishing a certificate
 * (in case the userDN for the user changed)
 *
 * @version $Id: CertReqHistoryData.java 34163 2020-01-02 15:00:17Z samuellb $
 */
@SuppressWarnings("deprecation")
@Entity
@Table(name = "CertReqHistoryData")
public class CertReqHistoryData extends ProtectedData implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(CertReqHistoryData.class);

  /** Param. */
  private String issuerDN;
  /** Param. */
  private String fingerprint;
  /** Param. */
  private String serialNumber;
  /** Param. */
  private long timestamp;
  /** Param. */
  private String userDataVO;
  /** Param. */
  private String username;
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /**
   * Entity Bean holding info about a request data at the time the certificate
   * was issued.
   *
   * @param incert the certificate issued
   * @param anissuerDN should be the same as CertTools.getIssuerDN(incert)
   * @param endEntityInformation the data used to issue the certificate.
   */
  public CertReqHistoryData(
      final Certificate incert,
      final String anissuerDN,
      final EndEntityInformation endEntityInformation) {
    // Exctract fields to store with the certificate.
    setFingerprint(CertTools.getFingerprintAsString(incert));
    setIssuerDN(anissuerDN);
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Creating certreqhistory data, serial="
              + CertTools.getSerialNumberAsString(incert)
              + ", issuer="
              + getIssuerDN());
    }
    setSerialNumber(CertTools.getSerialNumber(incert).toString());
    setTimestamp(new Date().getTime());
    setUsername(endEntityInformation.getUsername());
    storeEndEntityInformation(endEntityInformation);
  }

  private void storeEndEntityInformation(
      final EndEntityInformation endEntityInformation) {
    try {
      // Save the user admin data in xml encoding.
      final ByteArrayOutputStream baos = new ByteArrayOutputStream();
      try (XMLEncoder encoder = new XMLEncoder(baos)) {
        encoder.writeObject(endEntityInformation);
      }
      final String s = baos.toString("UTF-8");
      if (LOG.isDebugEnabled()) {
        LOG.debug(printEndEntityInformationXML("endEntityInformation:", s));
      }
      setUserDataVO(s);
    } catch (UnsupportedEncodingException e) {
      LOG.error("", e);
      throw new RuntimeException(e);
    }
  }

  /** Empty constructor.
   */
  public CertReqHistoryData() { }

  /**
   * DN of issuer of certificate Should not be used outside of entity bean, use
   * getCertReqHistory instead.
   *
   * @return issuer dn
   */
  // @Column
  public String getIssuerDN() {
    return issuerDN;
  }
  /**
   * Use setIssuer instead.
   *
   * @param anissuerDN issuer dn
   */
  public void setIssuerDN(final String anissuerDN) {
    this.issuerDN = anissuerDN;
  }

  /**
   * Fingerprint of certificate Should not be used outside of entity bean, use
   * getCertReqHistory instead.
   *
   * @return fingerprint
   */
  // @Id @Column
  public String getFingerprint() {
    return fingerprint;
  }
  /**
   * Fingerprint of certificate Shouldn't be set after creation.
   *
   * @param afingerprint fingerprint
   */
  public void setFingerprint(final String afingerprint) {
    this.fingerprint = afingerprint;
  }

  /**
   * Serialnumber formated as BigInteger.toString() Should not be used outside
   * of entity bean, use getCertReqHistory instead.
   *
   * @return serial number
   */
  // @Column
  public String getSerialNumber() {
    return serialNumber;
  }

  /**
   * Serialnumber formated as BigInteger.toString() Shouldn't be set after
   * creation.
   *
   * @param aserialNumber serial number
   */
  public void setSerialNumber(final String aserialNumber) {
    this.serialNumber = aserialNumber;
  }

  /**
   * Date formated as seconds since 1970 (== Date.getTime()) Should not be used
   * outside of entity bean, use getCertReqHistory instead.
   *
   * @return timestamp
   */
  // @Column
  public long getTimestamp() {
    return timestamp;
  }

  /**
   * Date formated as seconds since 1970 (== Date.getTime()) Shouldn't be set
   * after creation.
   *
   * @param atimestamp when certificate request info was stored
   */
  public void setTimestamp(final long atimestamp) {
    this.timestamp = atimestamp;
  }

  /**
   * UserDataVO in xmlencoded String format Should not be used outside of entity
   * bean, use getCertReqHistory instead.
   *
   * @return xmlencoded encoded UserDataVO
   */
  // @Column @Lob
  public String getUserDataVO() {
    return userDataVO;
  }

  /**
   * UserDataVO in xmlencoded String format Shouldn't be set after creation.
   *
   * @param auserDataVO xmlencoded encoded UserDataVO
   */
  public void setUserDataVO(final String auserDataVO) {
    this.userDataVO = auserDataVO;
  }

  /**
   * username in database Should not be used outside of entity bean, use
   * getCertReqHistory instead.
   *
   * @return username
   */
  // @Column
  public String getUsername() {
    return username;
  }

  /**
   * username Shouldn't be set after creation.
   *
   * @param ausername username
   */
  public void setUsername(final String ausername) {
    this.username = StringUtil.stripUsername(ausername);
  }

  /**
   * @return version
   */
  // @Version @Column
  public int getRowVersion() {
    return rowVersion;
  }

  /**
   * @param arowVersion version
   */
  public void setRowVersion(final int arowVersion) {
    this.rowVersion = arowVersion;
  }

  // @Column @Lob
  @Override
  public String getRowProtection() {
    return rowProtection;
  }

  @Override
  public void setRowProtection(final String arowProtection) {
    this.rowProtection = arowProtection;
  }

  //
  // Public business methods used to help us manage certificates
  //

  /**
   * Returns the value object containing the information of the entity bean.
   * This is the method that should be used to retreive cert req history
   * correctly.
   *
   * <p>NOTE: This method will try to repair broken XML and will in that case
   * update the database. This means that this method must always run in a
   * transaction!
   *
   * @return certificate request history object
   */
  @Transient
  public CertReqHistory getCertReqHistory() {

    return new CertReqHistory(
        this.getFingerprint(),
        this.getSerialNumber(),
        this.getIssuerDN(),
        this.getUsername(),
        new Date(this.getTimestamp()),
        decodeXML(getUserDataVO(), false));
  }

  /**
   * just used internally in the this class to indicate that the XML can not be
   * fixed.
   */
  private class NotPossibleToFixXML extends Exception {
    private static final long serialVersionUID = 3690860390706539637L;

    // just used internally in the this class to indicate that the XML can not
    // be fixed.
    NotPossibleToFixXML() {
      // do nothing
    }
  }

  /**
   * decode objects that have been serialized to xml. This method tries to fix
   * xml that has been broken by some characters missing in the end. This has
   * been found in some older DB during upgrade from EJBCA 3.4, and seemed to be
   * due to internationalized characters. This seemed to truncate the XML
   * somehow, and here we try to handle that in a nice way.
   *
   * @param sXML XML
   * @param lastTry Bool
   * @return Info
   */
  private EndEntityInformation decodeXML(
      final String sXML, final boolean lastTry) {
    final byte[] baXML = sXML.getBytes(StandardCharsets.UTF_8);
    EndEntityInformation endEntityInformation = null;
    // The EndEntityInformation object is not fully serializable by
    // XMLEncoder/Decoder
    // (the "type" field is not serialized correctly), so we set ignoreErrors to
    // true
    try (SecureXMLDecoder decoder =
        new SecureXMLDecoder(new ByteArrayInputStream(baXML), true)) {
      Object o = decoder.readObject();
      try {
        endEntityInformation = (EndEntityInformation) o;
      } catch (ClassCastException e) {
        if (LOG.isTraceEnabled()) {
          LOG.trace(
              "Trying to decode old type of CertReqHistoryData: "
                  + e.getMessage());
        }
        // It is probably an older object of type UserDataVO
        UserDataVO olddata = (UserDataVO) o;
        endEntityInformation = olddata.toEndEntityInformation();
      }
    } catch (Throwable t) { // NOPMD: catch all to try to repair
      // try to repair the end of the XML string.
      // this will only succeed if a limited number of chars is lost in the end
      // of the string
      // note that this code will not make anything worse and that it will not
      // be run if the XML can be encoded.
      //
      try {
        if (lastTry) {
          if (t instanceof IOException) {
            final String msg =
                "Failed to parse data map for certificate request history for '"
                    + getFingerprint()
                    + "': "
                    + t.getMessage();
            if (LOG.isDebugEnabled()) {
              LOG.debug(msg + ". Data:\n" + sXML);
            }
            throw new IllegalStateException(msg, t);
          } else if (t instanceof RuntimeException) {
            throw (RuntimeException) t;
          }
          return null;
        }
        final String sFixedXML =
            FixEndOfBrokenXML.fixXML(sXML, "string", "</void></object></java>");
        if (sFixedXML == null) {
          throw new NotPossibleToFixXML();
        }
        endEntityInformation = decodeXML(sFixedXML, true);
        if (endEntityInformation == null) {
          throw new NotPossibleToFixXML();
        }
        storeEndEntityInformation(
            endEntityInformation); // store it right so it does not have to be
        // repaired again.
        LOG.warn(
            printEndEntityInformationXML(
                "XML has been repaired. Trailing tags fixed. DB updated with"
                    + " correct XML.",
                sXML));
        return endEntityInformation;
      } catch (NotPossibleToFixXML e) {
        LOG.error(
            printEndEntityInformationXML(
                "Not possible to decode EndEntityInformation. No way to fix"
                    + " the XML.",
                sXML),
            t);
        return null;
      }
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          printEndEntityInformationXML(
              "Successfully decoded EndEntityInformation XML.", sXML));
    }
    /* Code that fixes broken XML that has actually been parsed.
     * It seems that the decoder is not checking for the java end tag.
     * Currently this is left out in order to not mess with working but
     * broken XML.
    if ( sXML.indexOf("<java")>0 && sXML.indexOf("</java>")<0 ) {
        storeEndEntityInformation(endEntityInformation); // store it right
    }
     */
    return endEntityInformation;
  }

  private String printEndEntityInformationXML(
      final String sComment, final String sXML) {
    final StringWriter sw = new StringWriter();
    final PrintWriter pw = new PrintWriter(sw);
    pw.println(sComment);
    pw.println("XMLDATA start on next line:");
    pw.print(sXML);
    pw.println("| end of XMLDATA. The char before '|' was the last XML.");
    pw.println();
    pw.println("Issuer DN: " + getIssuerDN());
    pw.println("Serial #" + getSerialNumber());
    pw.println("User name: " + getUsername());
    pw.println("Certificate fingerprint: " + getFingerprint());
    pw.println();
    return sw.toString();
  }

  //
  // Start Database integrity protection methods
  //

  @Transient
  @Override
  protected String getProtectString(final int version) {
    final ProtectionStringBuilder build = new ProtectionStringBuilder();
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build
        .append(getFingerprint())
        .append(getIssuerDN())
        .append(getSerialNumber())
        .append(getTimestamp())
        .append(getUserDataVO())
        .append(getUsername());
    return build.toString();
  }

  @Transient
  @Override
  protected int getProtectVersion() {
    return 1;
  }

  @PrePersist
  @PreUpdate
  @Override
  protected void protectData() {
    super.protectData();
  }

  @PostLoad
  @Override
  protected void verifyData() {
    super.verifyData();
  }

  @Override
  @Transient
  protected String getRowId() {
    return getFingerprint();
  }

  //
  // End Database integrity protection methods
  //

  //
  // Search functions.
  //

  /**
   * @param entityManager EM
   * @param fingerprint FP
   * @return the found entity instance or null if the entity does not exist
   */
  public static CertReqHistoryData findById(
      final EntityManager entityManager, final String fingerprint) {
    return entityManager.find(CertReqHistoryData.class, fingerprint);
  }

  /**
   * @param entityManager EM
   * @param issuerDN DN
   * @param serialNumber SN
   * @return return the query results as a List.
   */
  public static List<CertReqHistoryData> findByIssuerDNSerialNumber(
      final EntityManager entityManager,
      final String issuerDN,
      final String serialNumber) {
    final TypedQuery<CertReqHistoryData> query =
        entityManager.createQuery(
            "SELECT a FROM CertReqHistoryData a WHERE a.issuerDN=:issuerDN AND"
                + " a.serialNumber=:serialNumber",
            CertReqHistoryData.class);
    query.setParameter("issuerDN", issuerDN);
    query.setParameter("serialNumber", serialNumber);
    return query.getResultList();
  }

  /**
   * @param entityManager EM
   * @param username User
   * @return return the query results as a List.
   */
  public static List<CertReqHistoryData> findByUsername(
      final EntityManager entityManager, final String username) {
    final TypedQuery<CertReqHistoryData> query =
        entityManager.createQuery(
            "SELECT a FROM CertReqHistoryData a WHERE a.username=:username",
            CertReqHistoryData.class);
    query.setParameter("username", username);
    return query.getResultList();
  }
}
