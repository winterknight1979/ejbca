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
package org.cesecore.certificates.crl;

import java.io.Serializable;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.Date;
import java.util.List;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.Base64Util;
import org.cesecore.util.CertTools;
import org.cesecore.util.QueryResultWrapper;

/**
 * Representation of a CRL.
 *
 * @version $Id: CRLData.java 22592 2016-01-18 12:09:44Z marko $
 */
@Entity
@Table(name = "CRLData")
public class CRLData extends ProtectedData implements Serializable {

  private static final long serialVersionUID = 5542295476157001912L;

  /** Logger. */
  private static final Logger LOG = Logger.getLogger(CRLData.class);

  /** param. */
  private int cRLNumber;
  /** param. */
  private int deltaCRLIndicator;
  /** param. */
  private String issuerDN;
  /** param. */
  private String fingerprint;
  /** param. */
  private String cAFingerprint;
  /** param. */
  private long thisUpdate;
  /** param. */
  private long nextUpdate;
  /** param. */
  private String base64Crl;
  /** param. */
  private int rowVersion = 0;
  /** param. */
  private String rowProtection;

  /**
   * Entity holding info about a CRL. Create by sending in the CRL, which
   * extracts (from the crl) fingerprint (primary key), CRLNumber, issuerDN,
   * thisUpdate, nextUpdate. CAFingerprint is the hash of the CA certificate.
   *
   * @param incrl the (X509)CRL to be stored in the database.
   * @param number monotonically increasing CRL number
   * @param anIssuerDN DN
   * @param aThisUpdate Date
   * @param aNextUpdate Date of next update
   * @param cafingerprint FP
   * @param aDeltaCRLIndicator -1 for a normal CRL and 1 for a deltaCRL
   */
  public CRLData(
      final byte[] incrl,
      final int number,
      final String anIssuerDN,
      final Date aThisUpdate,
      final Date aNextUpdate,
      final String cafingerprint,
      final int aDeltaCRLIndicator) {
    String b64Crl = new String(Base64Util.encode(incrl));
    setBase64Crl(b64Crl);
    String fp = CertTools.getFingerprintAsString(incrl);
    setFingerprint(fp);
    // Make sure names are always looking the same
    String issuer = CertTools.stringToBCDNString(anIssuerDN);
    setIssuerDN(issuer);
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Creating crldata, fp="
              + fp
              + ", issuer="
              + issuer
              + ", crlNumber="
              + number
              + ", deltaCRLIndicator="
              + aDeltaCRLIndicator);
    }
    setCaFingerprint(cafingerprint);
    setCrlNumber(number);
    setThisUpdate(aThisUpdate);
    setNextUpdate(aNextUpdate);
    setDeltaCRLIndicator(aDeltaCRLIndicator);
  }

  /** Null constructor. */
  public CRLData() { }

  /**
   * @return num
   */
  // @Column
  public int getCrlNumber() {
    return cRLNumber;
  }

  /**
   * @param aCRLNumber Num
   */
  public void setCrlNumber(final int aCRLNumber) {
    this.cRLNumber = aCRLNumber;
  }

  /**
   * @return delta
   */
  // @Column
  public int getDeltaCRLIndicator() {
    return deltaCRLIndicator;
  }

  /**
   * @param aDeltaCRLIndicator delta
   */
  public void setDeltaCRLIndicator(final int aDeltaCRLIndicator) {
    this.deltaCRLIndicator = aDeltaCRLIndicator;
  }

  /**
   * @return DN
   */
  // @Column
  public String getIssuerDN() {
    return issuerDN;
  }

  /**
   * Use setIssuer instead.
   *
   * @param anIssuerDN DN
   * @see #setIssuer(String)
   */
  public void setIssuerDN(final String anIssuerDN) {
    this.issuerDN = anIssuerDN;
  }

  /**
   * @return FP
   */
  // @Id @Column
  public String getFingerprint() {
    return fingerprint;
  }

  /**
   * @param aFingerprint FP
   */
  public void setFingerprint(final String aFingerprint) {
    this.fingerprint = aFingerprint;
  }

  /**
   * @return FP
   */
  // @Column
  public String getCaFingerprint() {
    return cAFingerprint;
  }

  /**
   * @param aCAFingerprint FP
   */
  public void setCaFingerprint(final String aCAFingerprint) {
    this.cAFingerprint = aCAFingerprint;
  }

  /**
   * @return dtae
   */
  // @Column
  public long getThisUpdate() {
    return thisUpdate;
  }

  /**
   * Date formated as seconds since 1970 (== Date.getTime()).
   *
   * @param aThisUpdate Date
   */
  public void setThisUpdate(final long aThisUpdate) {
    this.thisUpdate = aThisUpdate;
  }

  /**
   * @return date
   */
  // @Column
  public long getNextUpdate() {
    return nextUpdate;
  }

  /**
   * Date formated as seconds since 1970 (== Date.getTime()).
   *
   * @param aNextUpdate date
   */
  public void setNextUpdate(final long aNextUpdate) {
    this.nextUpdate = aNextUpdate;
  }

  /**
   * @return CRL
   */
  // @Column @Lob
  public String getBase64Crl() {
    return base64Crl;
  }

  /**
   * @param aBase64Crl CRL
   */
  public void setBase64Crl(final String aBase64Crl) {
    this.base64Crl = aBase64Crl;
  }

  /**
   * @return version
   */
  // @Version @Column
  public int getRowVersion() {
    return rowVersion;
  }

  /**
   * @param aRowVersion version
   */
  public void setRowVersion(final int aRowVersion) {
    this.rowVersion = aRowVersion;
  }

  // @Column @Lob
  @Override
  public String getRowProtection() {
    return rowProtection;
  }

  @Override
  public void setRowProtection(final String aRowProtection) {
    this.rowProtection = aRowProtection;
  }

  //
  // Public methods used to help us manage CRLs
  //
  /**
   * @return CRL
   */
  @Transient
  public X509CRL getCRL() {
    X509CRL crl = null;
    try {
      String b64Crl = getBase64Crl();
      crl = CertTools.getCRLfromByteArray(Base64Util.decode(b64Crl.getBytes()));
    } catch (CRLException ce) {
      LOG.error("Can't decode CRL.", ce);
      return null;
    }
    return crl;
  }

  /**
   * @param incrl CRL
   */
  public void setCRL(final X509CRL incrl) {
    try {
      String b64Crl = new String(Base64Util.encode(incrl.getEncoded()));
      setBase64Crl(b64Crl);
    } catch (CRLException ce) {
      LOG.error("Can't extract DER encoded CRL.", ce);
    }
  }

  /**
   * @return CRL
   */
  @Transient
  public byte[] getCRLBytes() {
    byte[] crl = null;
    String b64Crl = getBase64Crl();
    crl = Base64Util.decode(b64Crl.getBytes());
    return crl;
  }

  /**
   * @param dn Issuer DN
   */
  public void setIssuer(final String dn) {
    setIssuerDN(CertTools.stringToBCDNString(dn));
  }

  /**
   * @param aThisUpdate Date
   */
  public void setThisUpdate(final Date aThisUpdate) {
    if (aThisUpdate == null) {
      setThisUpdate(-1L);
    }
    setThisUpdate(aThisUpdate.getTime());
  }

  /**
   * @param aNextUpdate Date
   */
  public void setNextUpdate(final Date aNextUpdate) {
    if (aNextUpdate == null) {
      setNextUpdate(-1L);
    }
    setNextUpdate(aNextUpdate.getTime());
  }

  //
  // Search functions.
  //

  /**
   * @param entityManager EM
   * @param fingerprint FP
   * @return the found entity instance or null if the entity does not exist
   */
  public static CRLData findByFingerprint(
      final EntityManager entityManager, final String fingerprint) {
    return entityManager.find(CRLData.class, fingerprint);
  }

  /**
   * @param entityManager EM
   * @param issuerDN DN
   * @param crlNumber CRL
   * @throws javax.persistence.NonUniqueResultException if more than one entity
   *     with the name exists
   * @return the found entity instance or null if the entity does not exist
   */
  public static CRLData findByIssuerDNAndCRLNumber(
      final EntityManager entityManager,
      final String issuerDN,
      final int crlNumber) {
    final Query query =
        entityManager.createQuery(
            "SELECT a FROM CRLData a WHERE a.issuerDN=:issuerDN AND"
                + " a.crlNumber=:crlNumber");
    query.setParameter("issuerDN", issuerDN);
    query.setParameter("crlNumber", crlNumber);
    return (CRLData) QueryResultWrapper.getSingleResult(query);
  }

  /**
   * @param entityManager EM
   * @param issuerDN DN
   * @return the all list of CRLData for specified issuerDN
   */
  public static List<CRLData> findByIssuerDN(
      final EntityManager entityManager, final String issuerDN) {
    final Query query =
        entityManager.createQuery(
            "SELECT a FROM CRLData a WHERE a.issuerDN=:issuerDN");
    query.setParameter("issuerDN", issuerDN);
    @SuppressWarnings("unchecked")
    List<CRLData> resultList = query.getResultList();
    return resultList;
  }

  /**
   * @param entityManager EM
   * @param issuerDN DN
   * @param deltaCRL CRL
   * @return the highest CRL number or null if no CRL for the specified issuer
   *     exists.
   */
  public static Integer findHighestCRLNumber(
      final EntityManager entityManager,
      final String issuerDN,
      final boolean deltaCRL) {
    Integer ret;
    if (deltaCRL) {
      final Query query =
          entityManager.createQuery(
              "SELECT MAX(a.crlNumber) FROM CRLData a WHERE"
                  + " a.issuerDN=:issuerDN AND a.deltaCRLIndicator>0");
      query.setParameter("issuerDN", issuerDN);
      ret = (Integer) QueryResultWrapper.getSingleResult(query);
    } else {
      final Query query =
          entityManager.createQuery(
              "SELECT MAX(a.crlNumber) FROM CRLData a WHERE"
                  + " a.issuerDN=:issuerDN AND a.deltaCRLIndicator=-1");
      query.setParameter("issuerDN", issuerDN);
      ret = (Integer) QueryResultWrapper.getSingleResult(query);
    }
    return ret;
  }

  //
  // Start Database integrity protection methods
  //

  @Transient
  @Override
  protected String getProtectString(final int version) {
    final ProtectionStringBuilder build = new ProtectionStringBuilder(3000);
    // What is important to protect here is the data that we define
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build
        .append(getFingerprint())
        .append(getCrlNumber())
        .append(getDeltaCRLIndicator())
        .append(getIssuerDN())
        .append(getCaFingerprint())
        .append(getThisUpdate())
        .append(getNextUpdate())
        .append(getBase64Crl());
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

}
