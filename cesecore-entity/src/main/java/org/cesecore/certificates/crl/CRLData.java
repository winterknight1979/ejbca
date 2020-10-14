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
import org.cesecore.util.Base64;
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

  private static final Logger log = Logger.getLogger(CRLData.class);

  private int cRLNumber;
  private int deltaCRLIndicator;
  private String issuerDN;
  private String fingerprint;
  private String cAFingerprint;
  private long thisUpdate;
  private long nextUpdate;
  private String base64Crl;
  private int rowVersion = 0;
  private String rowProtection;

  /**
   * Entity holding info about a CRL. Create by sending in the CRL, which
   * extracts (from the crl) fingerprint (primary key), CRLNumber, issuerDN,
   * thisUpdate, nextUpdate. CAFingerprint is the hash of the CA certificate.
   *
   * @param incrl the (X509)CRL to be stored in the database.
   * @param number monotonically increasing CRL number
   * @param issuerDN DN
   * @param thisUpdate Date
   * @param nextUpdate Date of next update
   * @param cafingerprint FP
   * @param deltaCRLIndicator -1 for a normal CRL and 1 for a deltaCRL
   */
  public CRLData(
      final byte[] incrl,
      final int number,
      final String issuerDN,
      final Date thisUpdate,
      final Date nextUpdate,
      final String cafingerprint,
      final int deltaCRLIndicator) {
    String b64Crl = new String(Base64.encode(incrl));
    setBase64Crl(b64Crl);
    String fp = CertTools.getFingerprintAsString(incrl);
    setFingerprint(fp);
    // Make sure names are always looking the same
    String issuer = CertTools.stringToBCDNString(issuerDN);
    setIssuerDN(issuer);
    if (log.isDebugEnabled()) {
      log.debug(
          "Creating crldata, fp="
              + fp
              + ", issuer="
              + issuer
              + ", crlNumber="
              + number
              + ", deltaCRLIndicator="
              + deltaCRLIndicator);
    }
    setCaFingerprint(cafingerprint);
    setCrlNumber(number);
    setThisUpdate(thisUpdate);
    setNextUpdate(nextUpdate);
    setDeltaCRLIndicator(deltaCRLIndicator);
  }

  public CRLData() {}

  // @Column
  public int getCrlNumber() {
    return cRLNumber;
  }

  public void setCrlNumber(final int cRLNumber) {
    this.cRLNumber = cRLNumber;
  }

  // @Column
  public int getDeltaCRLIndicator() {
    return deltaCRLIndicator;
  }

  public void setDeltaCRLIndicator(final int deltaCRLIndicator) {
    this.deltaCRLIndicator = deltaCRLIndicator;
  }

  // @Column
  public String getIssuerDN() {
    return issuerDN;
  }

  /**
   * Use setIssuer instead
   *
   * @param issuerDN DN
   * @see #setIssuer(String)
   */
  public void setIssuerDN(final String issuerDN) {
    this.issuerDN = issuerDN;
  }

  // @Id @Column
  public String getFingerprint() {
    return fingerprint;
  }

  public void setFingerprint(final String fingerprint) {
    this.fingerprint = fingerprint;
  }

  // @Column
  public String getCaFingerprint() {
    return cAFingerprint;
  }

  public void setCaFingerprint(final String cAFingerprint) {
    this.cAFingerprint = cAFingerprint;
  }

  // @Column
  public long getThisUpdate() {
    return thisUpdate;
  }

  /**
   * Date formated as seconds since 1970 (== Date.getTime())
   *
   * @param thisUpdate Date
   */
  public void setThisUpdate(final long thisUpdate) {
    this.thisUpdate = thisUpdate;
  }

  // @Column
  public long getNextUpdate() {
    return nextUpdate;
  }

  /**
   * Date formated as seconds since 1970 (== Date.getTime())
   *
   * @param nextUpdate date
   */
  public void setNextUpdate(final long nextUpdate) {
    this.nextUpdate = nextUpdate;
  }

  // @Column @Lob
  public String getBase64Crl() {
    return base64Crl;
  }

  public void setBase64Crl(final String base64Crl) {
    this.base64Crl = base64Crl;
  }

  // @Version @Column
  public int getRowVersion() {
    return rowVersion;
  }

  public void setRowVersion(final int rowVersion) {
    this.rowVersion = rowVersion;
  }

  // @Column @Lob
  @Override
  public String getRowProtection() {
    return rowProtection;
  }

  @Override
  public void setRowProtection(final String rowProtection) {
    this.rowProtection = rowProtection;
  }

  //
  // Public methods used to help us manage CRLs
  //
  @Transient
  public X509CRL getCRL() {
    X509CRL crl = null;
    try {
      String b64Crl = getBase64Crl();
      crl = CertTools.getCRLfromByteArray(Base64.decode(b64Crl.getBytes()));
    } catch (CRLException ce) {
      log.error("Can't decode CRL.", ce);
      return null;
    }
    return crl;
  }

  public void setCRL(final X509CRL incrl) {
    try {
      String b64Crl = new String(Base64.encode((incrl).getEncoded()));
      setBase64Crl(b64Crl);
    } catch (CRLException ce) {
      log.error("Can't extract DER encoded CRL.", ce);
    }
  }

  @Transient
  public byte[] getCRLBytes() {
    byte[] crl = null;
    String b64Crl = getBase64Crl();
    crl = Base64.decode(b64Crl.getBytes());
    return crl;
  }

  public void setIssuer(final String dn) {
    setIssuerDN(CertTools.stringToBCDNString(dn));
  }

  public void setThisUpdate(final Date thisUpdate) {
    if (thisUpdate == null) {
      setThisUpdate(-1L);
    }
    setThisUpdate(thisUpdate.getTime());
  }

  public void setNextUpdate(final Date nextUpdate) {
    if (nextUpdate == null) {
      setNextUpdate(-1L);
    }
    setNextUpdate(nextUpdate.getTime());
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
