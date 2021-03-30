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
package org.ejbca.ra;

import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang.StringUtils;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;

/**
 * UI representation of a certificate preview to be confirmed before enrollment.
 *
 * @version $Id: RaRequestPreview.java 28560 2018-03-27 12:39:10Z
 *     jekaterina_b_helmes $
 */
public class RaRequestPreview {

  // private static final Logger log = Logger.getLogger(RaRequestPreview.class);
      /** Param. */
  private String issuerDn = "";
  /** Param. */
  private String subjectDn = "";
  /** Param. */
  private String publicKeyAlgorithm = "";
  /** Param. */
  private String subjectAlternativeName = "";
  /** Param. */
  private String subjectDirectoryAttributes = "";
  /** Param. */
  private String validity = "";
  /** Param. */
  private List<String> keyUsages = new ArrayList<>();
  /** Param. */
  private List<String> extendedKeyUsages = new ArrayList<>();

  /** Param. */
  private boolean more = false;
  /** Param. */
  private int styleRowCallCounter = 0;

  /** Param. */
  public RaRequestPreview() { }

  /**
   * @param certificateProfile Profile
   */
  public final void updateCertificateProfile(
      final CertificateProfile certificateProfile) {
    if (certificateProfile == null) {
      return;
    }
    validity = certificateProfile.getEncodedValidity();
    keyUsages.clear();
    final boolean[] keyUsageArray = certificateProfile.getKeyUsage();
    for (int i = 0; i < keyUsageArray.length; i++) {
      if (keyUsageArray[i]) {
        keyUsages.add(String.valueOf(i));
      }
    }
    extendedKeyUsages.clear();
    final List<String> aextendedKeyUsages =
        certificateProfile.getExtendedKeyUsageOids();
    if (aextendedKeyUsages != null) {
      this.extendedKeyUsages.addAll(aextendedKeyUsages);
    }
  }

  /**
   * @param acaInfo info
   */
  public final void updateCA(final CAInfo acaInfo) {
    if (acaInfo == null) {
      return;
    }
    issuerDn = acaInfo.getSubjectDN();
  }

  /**
   * @param asubjectDn DN
   */
  public final void updateSubjectDn(final SubjectDn asubjectDn) {
    if (asubjectDn == null) {
      return;
    }
    this.subjectDn = asubjectDn.getUpdatedValue();
  }

  /**
   * @param asubjectAlternativeName name
   */
  public final void updateSubjectAlternativeName(
      final SubjectAlternativeName asubjectAlternativeName) {
    if (asubjectAlternativeName == null) {
      return;
    }
    this.subjectAlternativeName = asubjectAlternativeName.getUpdatedValue();
  }

  /**
   * @param asubjectDirectoryAttributes attrs
   */
  public final void updateSubjectDirectoryAttributes(
      final SubjectDirectoryAttributes asubjectDirectoryAttributes) {
    if (asubjectDirectoryAttributes == null) {
      return;
    }
    this.subjectDirectoryAttributes =
        asubjectDirectoryAttributes.getUpdatedValue();
  }

  /** @return true if more details should be shown */
  public final boolean isMore() {
    return more;
  }

  /**
   * @param amore bool
   */
  public final void setMore(final boolean amore) {
    this.more = amore;
    styleRowCallCounter = 0; // Reset
  }

  /** @return true every twice starting with every forth call */
  public final boolean isEven() {
    styleRowCallCounter++;
    return (styleRowCallCounter + 1) / 2 % 2 == 0;
  }

  /**
   * @return DN
   */
  public final String getSubjectDn() {
    return subjectDn;
  }

  /**
   * @param value String to enescape
   * @return value in unescaped RDN format
   */
  public final String getUnescapedRdnValue(final String value) {
    if (StringUtils.isNotEmpty(value)) {
      return org.ietf.ldap.LDAPDN.unescapeRDN(value);
    } else {
      return value;
    }
  }

  /**
   * @param asubjectDn DN
   */
  public void setSubjectDn(final String asubjectDn) {
    this.subjectDn = asubjectDn;
  }

  /**
   * @return algo
   */
  public String getPublicKeyAlgorithm() {
    return publicKeyAlgorithm;
  }

  /**
   * @param apublicKeyAlgorithm algo
   */
  public void setPublicKeyAlgorithm(final String apublicKeyAlgorithm) {
    this.publicKeyAlgorithm = apublicKeyAlgorithm;
  }

  /**
   * @return aname
   */
  public String getSubjectAlternativeName() {
    return subjectAlternativeName;
  }

  /**
   * @param asubjectAlternativeName aname
   */
  public void setSubjectAlternativeName(final String asubjectAlternativeName) {
    this.subjectAlternativeName = asubjectAlternativeName;
  }

  /**
   * @return attrs
   */
  public String getSubjectDirectoryAttributes() {
    return subjectDirectoryAttributes;
  }

  /**
   * @param asubjectDirectoryAttributes attre
   */
  public void setSubjectDirectoryAttributes(
      final String asubjectDirectoryAttributes) {
    this.subjectDirectoryAttributes = asubjectDirectoryAttributes;
  }

  /**
   * @return count
   */
  public int getStyleRowCallCounter() {
    return styleRowCallCounter;
  }

  /**
   * @param astyleRowCallCounter count
   */
  public void setStyleRowCallCounter(final int astyleRowCallCounter) {
    this.styleRowCallCounter = astyleRowCallCounter;
  }

  /**
   * @return bool
   */
  public boolean isSubjectDirectoryAttributesUsed() {
    return !subjectDirectoryAttributes.isEmpty() && isMore();
  }

  /**
   * @return bool
   */
  public boolean isSubjectAlternativeNameUsed() {
    return !subjectAlternativeName.isEmpty();
  }

  /**
   * @return bool
   */
  public boolean isAnyRequestDataPresent() {
    return !subjectDn.isEmpty()
        || !subjectAlternativeName.isEmpty()
        || !subjectDirectoryAttributes.isEmpty();
  }

  /** @return the issuerDn */
  public String getIssuerDn() {
    return issuerDn;
  }

  /** @param aissuerDn the issuerDn to set */
  public void setIssuerDn(final String aissuerDn) {
    this.issuerDn = aissuerDn;
  }

  /** @return the validity */
  public String getValidity() {
    return validity;
  }

  /** @param avalidity the validity to set */
  public void setValidity(final String avalidity) {
    this.validity = avalidity;
  }

  /**
   * @return list
   */
  public List<String> getKeyUsages() {
    return keyUsages;
  }

  /**
   * @param akeyUsages list
   */
  public void setKeyUsages(final List<String> akeyUsages) {
    this.keyUsages = akeyUsages;
  }

  /**
   * @return list
   */
  public List<String> getExtendedKeyUsages() {
    return extendedKeyUsages;
  }

  /**
   * @param anextendedKeyUsages list
   */
  public void setExtendedKeyUsages(final List<String> anextendedKeyUsages) {
    this.extendedKeyUsages = anextendedKeyUsages;
  }
}
