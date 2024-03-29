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
package org.ejbca.core.model.ca.certificateprofiles;

import java.io.Serializable;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.x509.PolicyQualifierId;

/**
 * NOTE! This class is only kept for upgrade and backwards compatibility
 * purposes. Replaced by
 * org.cesecore.certificates.certificateprofile.CertificatePolicy
 *
 * @version $Id: CertificatePolicy.java 19902 2014-09-30 14:32:24Z anatom $
 */
public class CertificatePolicy implements Serializable, Cloneable {

  /**
   * Warning changing this value will cause upgrades to fail, because it has
   * been serialized in the database (in XML). DONT CHANGE THIS!
   */
  private static final long serialVersionUID = -6384137742329979249L;

  // Policy qualifier Ids are taken from BC classes
  /** ID. */
  public static final String ID_QT_CPS = PolicyQualifierId.id_qt_cps.getId();
  /** ID. */
  public static final String ID_QT_UNNOTICE =
      PolicyQualifierId.id_qt_unotice.getId();

  /** The special <code>anyPolicy</code> policy OID. */
  public static final String ANY_POLICY_OID = "2.5.29.32.0";

  /** ID. */
  private String policyID;
  /** CPS uri.*/
  private String qualifierId;
  /** user notice text. */
  private String qualifier;

  /** Null constructor. */
  public CertificatePolicy() {
    super();
  }

  /**
   * @param aPolicyID ID
   * @param aQualifierId QUD
   * @param aQualifier qualifier
   */
  public CertificatePolicy(
      final String aPolicyID,
      final String aQualifierId,
      final String aQualifier) {
    this.policyID = aPolicyID;
    this.qualifierId = aQualifierId;
    this.qualifier = aQualifier;
  }

  /** @return the policyID */
  public String getPolicyID() {
    return this.policyID;
  }

  /** @param aPolicyID the policyID to set */
  public void setPolicyID(final String aPolicyID) {
    this.policyID = aPolicyID;
  }

  /** @return the qualifier string */
  public String getQualifier() {
    return this.qualifier;
  }

  /** @param aQualifier the uri to set */
  public void setQualifier(final String aQualifier) {
    this.qualifier = aQualifier;
  }

  /** @return the QualifierId */
  public String getQualifierId() {
    return this.qualifierId;
  }

  /** @param aQualifierId the QualifierId to set */
  public void setQualifierId(final String aQualifierId) {
    this.qualifierId = aQualifierId;
  }

  /** @see java.lang.Object#clone() */
  @Override
  protected Object clone()
      throws CloneNotSupportedException { // NOPMD by tomas on 1/7/11 1:04 PM
    return new CertificatePolicy(
        this.policyID, this.qualifierId, this.qualifier);
  }

  /** @see java.lang.Object#toString() */
  @Override
  public String toString() {
    final StringBuilder strBuffer = new StringBuilder(100);
    strBuffer.append("CertificatePolicy(policyID=");
    strBuffer.append(this.policyID);
    strBuffer.append(", qualifierId=");
    strBuffer.append(this.qualifierId);
    strBuffer.append(", qualifier=");
    strBuffer.append(this.qualifier);
    strBuffer.append(')');
    return strBuffer.toString();
  }

  /** @see java.lang.Object#equals(java.lang.Object) */
  @Override
  public boolean equals(final Object obj) { // NOPMD
    if (obj == null || !(obj instanceof CertificatePolicy)) {
      return false;
    }
    final CertificatePolicy policy = (CertificatePolicy) obj;

    // We want to let both null and "" be the same value here, i.e. an empty
    // value
    // Simply because, especially in gui code, it is somewhat tricky to trust
    // which is a non-existant value
    boolean policyeq = false;
    if (StringUtils.isEmpty(policy.getPolicyID())
        && StringUtils.isEmpty(this.policyID)) {
      policyeq = true;
    } else if (StringUtils.equals(policy.getPolicyID(), this.policyID)) {
      policyeq = true;
    }
    boolean qualifierideq = false;
    if (StringUtils.isEmpty(policy.getQualifierId())
        && StringUtils.isEmpty(this.qualifierId)) {
      qualifierideq = true;
    } else if (StringUtils.equals(policy.getQualifierId(), this.qualifierId)) {
      qualifierideq = true;
    }
    boolean aQualifier = false;
    if (StringUtils.isEmpty(policy.getQualifier())
        && StringUtils.isEmpty(this.qualifier)) {
      aQualifier = true;
    } else if (StringUtils.equals(policy.getQualifier(), this.qualifier)) {
      aQualifier = true;
    }
    return policyeq && qualifierideq && aQualifier;
  }


  /** @see java.lang.Object#hashCode() */
  @Override
  public int hashCode() {
    return this.toString().hashCode();
  }
}
