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
package org.cesecore.certificates.certificateprofile;

import java.io.Serializable;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.x509.PolicyQualifierId;

/**
 * Class encapsulating the CertificatePolicy X509 certificate extensions. See
 * rfc3280. Contains an OID and optionally a policy qualifier. Several
 * CertificatePolicy classes can be created with the same oid, for different
 * qualifiers
 *
 * @version $Id: CertificatePolicy.java 24292 2016-09-03 16:23:37Z anatom $
 */
public class CertificatePolicy implements Serializable, Cloneable {

  /**
   * Warning changing this value will cause upgrades to fail, because it has
   * been serialized in the database (in XML). DONT CHANGE THIS!
   */
  private static final long serialVersionUID = -6384137742329979249L;

  // Policy qualifier Ids are taken from BC classes.
  /** CPS. */
  public static final String ID_QT_CPS = PolicyQualifierId.id_qt_cps.getId();
  /** Unnoticed. */
  public static final String ID_QT_UNNOTICE =
      PolicyQualifierId.id_qt_unotice.getId();

  /** The special <code>anyPolicy</code> policy OID. */
  public static final String ANY_POLICY_OID = "2.5.29.32.0";
  /** ID. */
  private String policyID;
  /** CPS uri. */
  private String qualifierId;
  /** user notice text. */
  private String qualifier;

  /** Default constructor. */
  public CertificatePolicy() {
    super();
  }

  /**
   * @param aPolicyID policy ID
   * @param aQualifierId PolicyQualifierId.id_qt_cps,
   *     PolicyQualifierId.id_qt_unotice or null
   * @param aQualifier cps URI or user notice text depending on qualifierId, or
   *     null if qualifierId is null
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

  /** @param aQualifier the Qualifier to set */
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

  @Override
  protected Object clone()
      throws CloneNotSupportedException { // NOPMD by tomas on 1/7/11 1:04 PM
    return new CertificatePolicy(
        this.policyID, this.qualifierId, this.qualifier);
  }

  @Override
  public String toString() {
    final StringBuilder strBuilder = new StringBuilder(100);

    strBuilder.append("CertificatePolicy(policyID=");
    strBuilder.append(this.policyID);
    strBuilder.append(", qualifierId=");
    strBuilder.append(this.qualifierId);
    strBuilder.append(", qualifier=");
    strBuilder.append(this.qualifier);
    strBuilder.append(')');

    return strBuilder.toString();
  }

  @Override
  public boolean equals(final Object obj) {
    if (obj == null || !(obj instanceof CertificatePolicy)) {
      return false;
    }
    final CertificatePolicy policy = (CertificatePolicy) obj;

    // We want to let both null and "" be the same value here, i.e. an empty
    // value
    // Simply because, especially in gui code, it is somewhat tricky to trust
    // which is a non-existant value
    boolean policyeq = getPolicyEq(policy);
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

/**
 * @param policy Pol
 * @return Bool
 */
private boolean getPolicyEq(final CertificatePolicy policy) {
    boolean policyeq = false;
    if (StringUtils.isEmpty(policy.getPolicyID())
        && StringUtils.isEmpty(this.policyID)) {
      policyeq = true;
    } else if (StringUtils.equals(policy.getPolicyID(), this.policyID)) {
      policyeq = true;
    }
    return policyeq;
}

  @Override
  public int hashCode() {
    return this.toString().hashCode();
  }
}
