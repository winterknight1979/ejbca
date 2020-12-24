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

package org.ejbca.ui.web.pub.retrieve;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.util.CertTools;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.ca.sign.SignSession;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.CertificateView;

/**
 * This bean performs a number of certificate searches for the public web.
 *
 * <p>To make it easy to use from JSTL pages, most methods take no arguments.
 * The arguments are supplied as member variables instead. <br>
 *
 * @version $Id: CertificateFinderBean.java 28543 2018-03-23 06:52:44Z
 *     jekaterina_b_helmes $
 */
public class CertificateFinderBean {

      /** Param. */
  private static final Logger LOG =
      Logger.getLogger(CertificateFinderBean.class);

  /** Param. */
  private final EjbLocalHelper ejb = new EjbLocalHelper();
  /** Param. */
  private final SignSession mSignSession = ejb.getSignSession();
  /** Param. */
  private final CaSessionLocal caSession = ejb.getCaSession();
  /** Param. */
  private final CertificateStoreSessionLocal mStoreSession =
      ejb.getCertificateStoreSession();

  /**
   * This member is used by the JSP pages to indicate which CA they are
   * interested in. It is used by getCAInfo().
   */
  private int mCurrentCA;

  // Used to store the result of lookupCertificateInfo
  /** Param. */
  private String issuerDN;
  /** Param. */
  private String subjectDN;
  /** Param. */
  private String serialNumber;
  /** Param. */
  private String fingerprint;

  /**
   * Empty default constructor. NOTE: Call initialize() after creating this
   * object.
   */
  public CertificateFinderBean() { }

  /**
   * @return CAs
   */
  public Collection<Integer> getAvailableCAs() {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getAvailableCAs()");
    }
    return caSession.getAllCaIds();
  }

  /**
   * @return CA
   */
  public int getCurrentCA() {
    return mCurrentCA;
  }

  /**
   * @return bool
   */
  public boolean existsDeltaCrlForCurrentCA() {
    return ejb.getCrlStoreSession()
            .getLastCRLInfo(getCAInfo().getSubjectDN(), true)
        != null;
  }

  /**
   * @param currentCA CA
   */
  public void setCurrentCA(final Integer currentCA) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">setCurrentCA(" + currentCA + ")");
    }
    mCurrentCA = currentCA;
  }

  /**
   * @return info
   */
  public CAInfo getCAInfo() {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getCAInfo() currentCA = " + mCurrentCA);
    }
    CAInfo cainfo = caSession.getCAInfoInternal(mCurrentCA);
    if (cainfo == null) {
      LOG.info("CA does not exist : " + mCurrentCA);
    }
    return cainfo;
  }

  /**
   * @return chain
   */
  public Collection<CertificateGuiInfo> getCACertificateChain() {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getCACertificateChain() currentCA = " + mCurrentCA);
    }
    // Make a collection of CertificateGuiInfo instead of the real certificate
    ArrayList<CertificateGuiInfo> ret = new ArrayList<>();
    Collection<Certificate> certs =
        mSignSession.getCertificateChain(mCurrentCA);
    for (Certificate cert : certs) {
      ret.add(new CertificateGuiInfo(cert));
    }

    return ret;
  }

  /**
   * @return info
   */
  public Collection<CertificateGuiInfo> getCACertificateChainReversed() {
    Collection<CertificateGuiInfo> ret = getCACertificateChain();
    if (ret != null) {
      Collections.reverse((ArrayList<CertificateGuiInfo>) ret);
    }
    return ret;
  }

  /**
   * @return DN
   */
  public String getCADN() {
    String ret = "Unauthorized";
    final Collection<Certificate> certs =
        this.mSignSession.getCertificateChain(this.mCurrentCA);
    if (certs == null || certs.isEmpty()) {
      return "";
    }
    final Certificate cert = certs.iterator().next();
    ret = CertTools.getSubjectDN(cert);

    return ret;
  }

  /**
   * Get revocation info for a certificate. This method fills in the supplied
   * RevokedCertInfo object with data about a certificate. Since Java uses "call
   * by reference" this works fine, but we can't create our own object because
   * the caller doesn't read the reference when unwinding the stack after this
   * method returns.
   *
   * @param anissuerDN DN of the certificate's issuer
   * @param oserialNumber The serial number of the certificate
   * @param result An allocated object. Data about the certificate is entered in
   *     the result object by this method. If no info can be found (e.g., if the
   *     certificate does not exist), the revocationDate and userCertificate
   *     fields of result are set to null.
   */
  public void lookupRevokedInfo(
      final String anissuerDN,
      final String oserialNumber,
      final RevokedCertInfo result) {
    String aserialNumber = oserialNumber;
    aserialNumber =
        ("0000000000000000" + aserialNumber)
          .substring(aserialNumber.length()); // Pad with zeroes up to 16 chars
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">lookupRevokedInfo("
              + anissuerDN
              + ", "
              + aserialNumber
              + ", "
              + result
              + ")");
    }
    if (result == null) {
      return; // There's nothing we can do here.
    }
    try {
      BigInteger serialBignum =
          new BigInteger(Hex.decode(StringUtils.trimToEmpty(aserialNumber)));
      CertificateStatus info =
          mStoreSession.getStatus(
              StringUtils.trimToEmpty(anissuerDN), serialBignum);
      if (info.equals(CertificateStatus.NOT_AVAILABLE)) {
        result.setRevocationDate(null);
        result.setUserCertificate(null);
      } else {
        result.setReason(info.getRevocationReason());
        result.setRevocationDate(info.getRevocationDate());
        result.setUserCertificate(serialBignum);
      }
    } catch (NumberFormatException e) {
      LOG.info(
          "Invalid serial number entered (NumberFormatException): "
              + aserialNumber
              + ": "
              + e.getMessage());
    } catch (StringIndexOutOfBoundsException e) {
      LOG.info(
          "Invalid serial number entered (StringIndexOutOfBoundsException): "
              + aserialNumber
              + ": "
              + e.getMessage());
    } catch (DecoderException e) {
      LOG.info(
          "Invalid serial number entered (DecoderException): "
              + aserialNumber
              + ": "
              + e.getMessage());
    }
  }

  /**
   * Uses the store session to look up all certificates for a subject. The
   * parameter <code>result</code> is updated so that it contains the
   * certificates as CertificateView objects.
   *
   * @param subject The DN of the subject
   * @param result a Collection (not null) that will be filled by
   *     CertificateView objects
   */
  public void lookupCertificatesBySubject(
      final String subject, final Collection<CertificateView> result) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">lookupCertificatesBySubject(" + subject + ", " + result + ")");
    }
    if (result == null) {
      return; // There's nothing we can do here.
    }
    result.clear();
    if (subject == null) {
      return; // We can't lookup any certificates, so return with an empty
              // result.
    }
    final List<CertificateDataWrapper> cdws =
        mStoreSession.getCertificateDatasBySubject(subject);
    Collections.sort(cdws);
    for (final CertificateDataWrapper cdw : cdws) {
      // TODO: CertificateView is located in web.admin package, but this is
      // web.pub package...
      result.add(new CertificateView(cdw));
    }
  }

  /**
   * Looks up a certificate information by issuer and serial number. The
   * information can be accessed by getter methods in this class.
   *
   * @param issuer issuer
   * @param serno SN
   * @see #getIssuerDN()
   * @see #getSubjectDN()
   * @see #getSerialNumber()
   */
  public void lookupCertificateInfo(final String issuer, final String serno) {
    BigInteger sernoBigInt = CertTools.getSerialNumberFromString(serno);
    Certificate cert =
        mStoreSession.findCertificateByIssuerAndSerno(issuer, sernoBigInt);
    if (cert != null) {
      this.issuerDN = CertTools.getIssuerDN(cert);
      this.subjectDN = CertTools.getSubjectDN(cert);
      this.serialNumber = CertTools.getSerialNumberAsString(cert);
      this.fingerprint = CertTools.getFingerprintAsString(cert);
    }
  }

  /**
   * @return the Issuer DN string of the current certificate.
   * @see #lookupCertificateInfo(String, String)
   */
  public String getIssuerDN() {
    return issuerDN;
  }

  /**
   * @return the Subject DN string of the current certificate.
   * @see #lookupCertificateInfo(String, String)
   */
  public String getSubjectDN() {
    return subjectDN;
  }

  /**
   * @return the Subject DN string of the current certificate in unescaped RDN
   *     format
   */
  public final String getSubjectDnUnescapedRdnValue() {
    if (StringUtils.isNotEmpty(subjectDN)) {
      return org.ietf.ldap.LDAPDN.unescapeRDN(subjectDN);
    } else {
      return subjectDN;
    }
  }

  /**
   * @return the Subject DN string of the current certificate URL-encoded using
   *     the current configured character set
   * @see #lookupCertificateInfo(String, String)
   */
  public String getSubjectDNEncoded() {
    return getHttpParamAsUrlEncoded(subjectDN);
  }

  /**
   * @return the serial number hex string of the current certificate.
   * @see #lookupCertificateInfo(String, String)
   */
  public String getSerialNumber() {
    return serialNumber;
  }

  /**
   * @return the fingerprint string of the current certificate.
   * @see #lookupCertificateInfo(String, String)
   */
  public String getFingerprint() {
    return fingerprint;
  }

  /**
   * @param param param
   * @return the param as it's URL encoded counterpart, taking the configured
   *     encoding into account.
   */
  private String getHttpParamAsUrlEncoded(final String param) {
    final String encoding = WebConfiguration.getWebContentEncoding();
    try {
      return URLEncoder.encode(param, encoding);
    } catch (UnsupportedEncodingException e) {
      throw new IllegalStateException(
          "The property 'web.contentencoding' is set to "
              + encoding
              + ", but this encoding is not available on this system.",
          e);
    }
  }
}
