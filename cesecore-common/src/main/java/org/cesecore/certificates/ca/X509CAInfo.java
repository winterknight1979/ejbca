/**********************a***************************************************
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
package org.cesecore.certificates.ca;

import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.util.CertTools;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.StringTools;

/**
 * Holds non-sensitive information about a X509CA.
 *
 * @version $Id: X509CAInfo.java 34456 2020-02-06 18:36:20Z anatom $
 */
public class X509CAInfo extends CAInfo {

  private static final long serialVersionUID = 2L;
  /** Policies. */
  private List<CertificatePolicy> policies;
  /** ID. */
  private boolean useauthoritykeyidentifier;
  /** Key. */
  private boolean authoritykeyidentifiercritical;
  /** CRL. */
  private boolean usecrlnumber;
  /** Critical. */
  private boolean crlnumbercritical;
  /** Dist. */
  private String defaultcrldistpoint;
  /** Issuer. */
  private String defaultcrlissuer;
  /** Locator. */
  private String defaultocsplocator;
  /** CRL. */
  private String cadefinedfreshestcrl;
  /** Name. */
  private String subjectaltname;
  /** UTF. */
  private boolean useUTF8PolicyText;
  /** Printable. */
  private boolean usePrintableStringSubjectDN;
  /** LDAP. */
  private boolean useLdapDNOrder;
  /** Dist. */
  private boolean useCrlDistributionPointOnCrl;
  /** Critical. */
  private boolean crlDistributionPointOnCrlCritical;
  /** Secret. */
  private String cmpRaAuthSecret = "";
  /** Access. */
  private List<String> authorityInformationAccess;
  /** URIs. */
  private List<String> certificateAiaDefaultCaIssuerUri;
  /** Constraints. */
  private List<String> nameConstraintsPermitted;
  /** Constraints. */
  private List<String> nameConstraintsExcluded;
  /** CDP. */
  private String externalCdp;
  /** Changed. */
  private boolean nameChanged;
  /** SN size. */
  private int caSerialNumberOctetSize;

  /**
   * This constructor can be used when creating a CA. This constructor uses
   * defaults for the fields that are not specified.
   *
   * @param subjectdn DN
   * @param name Name
   * @param status Status
   * @param certificateProfileId Profile
   * @param encodedValidity Vlidity
   * @param signedby Signer
   * @param certificatechain Certs
   * @param catoken Token
   */
  public X509CAInfo(
      final String subjectdn,
      final String name,
      final int status,
      final int certificateProfileId,
      final String encodedValidity,
      final int signedby,
      final Collection<Certificate> certificatechain,
      final CAToken catoken) {
    this(
        subjectdn,
        name,
        status, // CA status (CAConstants.CA_ACTIVE, etc.)
        new Date(), // update time
        "", // Subject Alternative name
        certificateProfileId, // CA certificate profile
        0, // default ca profile
        false, // default is certificate data table
        encodedValidity,
        null, // Expiretime
        CAInfo.CATYPE_X509, // CA type (X509/CVC)
        signedby, // Signed by CA
        certificatechain, // Certificate chain
        catoken, // CA Token
        "", // Description
        CesecoreConfiguration
            .getSerialNumberOctetSizeForNewCa(), // serial number octet size
        -1, // Revocation reason
        null, // Revocation date
        null, // PolicyId
        1 * SimpleTime.MILLISECONDS_PER_DAY, // CRLPeriod
        0L, // CRLIssueInterval
        10 * SimpleTime.MILLISECONDS_PER_MINUTE, // CRLOverlapTime
        0L, // DeltaCRLPeriod
        new ArrayList<Integer>(),
        new ArrayList<Integer>(),
        true, // Authority Key Identifier
        false, // Authority Key Identifier Critical
        true, // CRL Number
        false, // CRL Number Critical
        null, // defaultcrldistpoint
        null, // defaultcrlissuer
        null, // defaultocsplocator
        null, // CRL Authority Information Access (AIA) extension
        null, // Certificate AIA default CA issuer URI
        null,
        null, // Name Constraints (permitted/excluded)
        null, // defaultfreshestcrl
        true, // Finish User
        new ArrayList<ExtendedCAServiceInfo>(), // no extended services
        false, // use default utf8 settings
        new HashMap<ApprovalRequestType, Integer>(), // approvals
        false, // Use UTF8 subject DN by default
        true, // Use LDAP DN order by default
        false, // Use CRL Distribution Point on CRL
        false, // CRL Distribution Point on CRL critical
        true, // Include in HealthCheck
        true, // isDoEnforceUniquePublicKeys
        true, // isDoEnforceUniqueDistinguishedName
        false, // isDoEnforceUniqueSubjectDNSerialnumber
        false, // useCertReqHistory
        true, // useUserStorage
        true, // useCertificateStorage
        false, // acceptRevocationNonExistingEntry
        null, // cmpRaAuthSecret
        false // keepExpiredCertsOnCRL
        );
  }

  /**
   * Constructor that should be used when creating CA and retrieving CA info.
   * Please use the shorter form if you do not need to set all of the values.
   *
   * @param subjectDn the Subject DN of the CA as found in the certificate
   * @param name the name of the CA shown in EJBCA, can be changed by the user
   * @param status the operational status of the CA, one of the constants in
   *     {@link CAConstants}
   * @param updateTime the last time this CA was updated, normally the current
   *     date and time
   * @param asubjectaltname the Subject Alternative Name (SAN) of the CA, as
   *     found in the certificate
   * @param certificateprofileid the ID of the certificate profile for this CA
   * @param defaultCertprofileId the id of default cetificate profile for
   *     certificates this CA issues
   * @param useNoConflictCertificateData should use NoConflictCertificate data
   *     table to write to
   * @param encodedValidity the validity of this CA as a human-readable string,
   *     e.g. 25y
   * @param expiretime the date when this CA expires
   * @param catype the type of CA, in this case CAInfo.CATYPE_X509
   * @param signedBy the id of the CA which signed this CA
   * @param certificatechain the certificate chain containing the CA certificate
   *     of this CA
   * @param catoken the CA token for this CA, containing e.g. a reference to the
   *     crypto token
   * @param description a text describing this CA
   * @param acaSerialNumberOctetSize serial number octet size for this CA
   * @param revocationReason the reason why this CA was revoked, or -1 if not
   *     revoked
   * @param revocationDate the date of revocation, or null if not revoked
   * @param apolicies a policy OID
   * @param crlperiod the CRL validity period in ms
   * @param crlIssueInterval how often in ms the CRLs should be distributed,
   *     e.g. 3600000 will generate a new CRL every hour
   * @param crlOverlapTime the validity overlap in ms for a subsequent CRL, e.g.
   *     5000 will generate a CRL 5m before the previous CRL expires
   * @param deltacrlperiod how often Delta CRLs should be distributed
   * @param crlpublishers a collection of publisher IDs for this CA
   * @param keyValidators a collection of key validator IDs for this CA
   * @param auseauthoritykeyidentifier bool
   * @param aauthoritykeyidentifiercritical bool
   * @param ausecrlnumber bool
   * @param acrlnumbercritical bool
   * @param adefaultcrldistpoint the URI of the default CRL distribution point
   * @param adefaultcrlissuer Issuer
   * @param defaultocspservicelocator Locator
   * @param aauthorityInformationAccess Acces
   * @param acertificateAiaDefaultCaIssuerUri Issuer URI
   * @param anameConstraintsPermitted a list of name constraints which should be
   *     permitted
   * @param anameConstraintsExcluded a list of name constraints which should be
   *     excluded
   * @param acadefinedfreshestcrl CRL
   * @param finishuser bool
   * @param extendedcaserviceinfos bool
   * @param auseUTF8PolicyText bool
   * @param approvals a map of approval profiles which should be used for
   *     different operations
   * @param ausePrintableStringSubjectDN bool
   * @param auseLdapDnOrder biik
   * @param auseCrlDistributionPointOnCrl bool
   * @param acrlDistributionPointOnCrlCritical bool
   * @param includeInHealthCheck enable healthcheck for this CA
   * @param adoEnforceUniquePublicKeys bool
   * @param adoEnforceUniqueDistinguishedName bool
   * @param adoEnforceUniqueSubjectDNSerialnumber bool
   * @param auseCertReqHistory bool
   * @param auseUserStorage bool
   * @param auseCertificateStorage bool
   * @param aacceptRevocationNonExistingEntry bool
   * @param acmpRaAuthSecret bool
   * @param keepExpiredCertsOnCRL bool
   */
  private X509CAInfo(
      final String subjectDn,
      final String name,
      final int status,
      final Date updateTime,
      final String asubjectaltname,
      final int certificateprofileid,
      final int defaultCertprofileId,
      final boolean useNoConflictCertificateData,
      final String encodedValidity,
      final Date expiretime,
      final int catype,
      final int signedBy,
      final Collection<Certificate> certificatechain,
      final CAToken catoken,
      final String description,
      final int acaSerialNumberOctetSize,
      final int revocationReason,
      final Date revocationDate,
      final List<CertificatePolicy> apolicies,
      final long crlperiod,
      final long crlIssueInterval,
      final long crlOverlapTime,
      final long deltacrlperiod,
      final Collection<Integer> crlpublishers,
      final Collection<Integer> keyValidators,
      final boolean auseauthoritykeyidentifier,
      final boolean aauthoritykeyidentifiercritical,
      final boolean ausecrlnumber,
      final boolean acrlnumbercritical,
      final String adefaultcrldistpoint,
      final String adefaultcrlissuer,
      final String defaultocspservicelocator,
      final List<String> aauthorityInformationAccess,
      final List<String> acertificateAiaDefaultCaIssuerUri,
      final List<String> anameConstraintsPermitted,
      final List<String> anameConstraintsExcluded,
      final String acadefinedfreshestcrl,
      final boolean finishuser,
      final Collection<ExtendedCAServiceInfo> extendedcaserviceinfos,
      final boolean auseUTF8PolicyText,
      final Map<ApprovalRequestType, Integer> approvals,
      final boolean ausePrintableStringSubjectDN,
      final boolean auseLdapDnOrder,
      final boolean auseCrlDistributionPointOnCrl,
      final boolean acrlDistributionPointOnCrlCritical,
      final boolean includeInHealthCheck,
      final boolean adoEnforceUniquePublicKeys,
      final boolean adoEnforceUniqueDistinguishedName,
      final boolean adoEnforceUniqueSubjectDNSerialnumber,
      final boolean auseCertReqHistory,
      final boolean auseUserStorage,
      final boolean auseCertificateStorage,
      final boolean aacceptRevocationNonExistingEntry,
      final String acmpRaAuthSecret,
      final boolean keepExpiredCertsOnCRL) {
    this.subjectdn = CertTools.stringToBCDNString(StringTools.strip(subjectDn));
    this.caid = CertTools.stringToBCDNString(this.subjectdn).hashCode();
    this.name = name;
    this.status = status;
    this.updatetime = updateTime;
    this.encodedValidity = encodedValidity;
    this.expiretime = expiretime;
    this.catype = catype;
    this.signedby = signedBy;
    // Due to a bug in Glassfish v1 (fixed in v2), we used to have to make sure
    // all certificates in this
    // Array were of SUNs own provider, using
    // CertTools.SYSTEM_SECURITY_PROVIDER.
    // As of EJBCA 3.9.3 we decided that we don't have to support Glassfish v1
    // anymore.
    try {
      if (certificatechain != null) {
        X509Certificate[] certs =
            certificatechain.toArray(
                new X509Certificate[certificatechain.size()]);
        List<Certificate> list =
            CertTools.getCertCollectionFromArray(certs, null);
        setCertificateChain(list);
      } else {
        setCertificateChain(null);
      }
    } catch (CertificateException e) {
      throw new IllegalArgumentException(e);
    } catch (NoSuchProviderException e) {
      throw new IllegalArgumentException(e);
    }
    this.catoken = catoken;
    this.description = description;
    setRevocationReason(revocationReason);
    this.revocationDate = revocationDate;
    this.policies = apolicies;
    this.crlperiod = crlperiod;
    this.crlIssueInterval = crlIssueInterval;
    this.crlOverlapTime = crlOverlapTime;
    this.deltacrlperiod = deltacrlperiod;
    this.crlpublishers = crlpublishers;
    this.validators = keyValidators;
    this.useauthoritykeyidentifier = auseauthoritykeyidentifier;
    this.authoritykeyidentifiercritical = aauthoritykeyidentifiercritical;
    this.usecrlnumber = ausecrlnumber;
    this.crlnumbercritical = acrlnumbercritical;
    this.defaultcrldistpoint = adefaultcrldistpoint;
    this.defaultcrlissuer = adefaultcrlissuer;
    this.defaultocsplocator = defaultocspservicelocator;
    this.cadefinedfreshestcrl = acadefinedfreshestcrl;
    this.finishuser = finishuser;
    this.subjectaltname = asubjectaltname;
    this.certificateprofileid = certificateprofileid;
    this.defaultCertificateProfileId = defaultCertprofileId;
    this.extendedcaserviceinfos = extendedcaserviceinfos;
    this.useUTF8PolicyText = auseUTF8PolicyText;
    setApprovals(approvals);
    this.usePrintableStringSubjectDN = ausePrintableStringSubjectDN;
    this.useLdapDNOrder = auseLdapDnOrder;
    this.useCrlDistributionPointOnCrl = auseCrlDistributionPointOnCrl;
    this.crlDistributionPointOnCrlCritical = acrlDistributionPointOnCrlCritical;
    this.includeInHealthCheck = includeInHealthCheck;
    this.doEnforceUniquePublicKeys = adoEnforceUniquePublicKeys;
    this.doEnforceUniqueDistinguishedName = adoEnforceUniqueDistinguishedName;
    this.doEnforceUniqueSubjectDNSerialnumber =
        adoEnforceUniqueSubjectDNSerialnumber;
    this.useCertReqHistory = auseCertReqHistory;
    this.useUserStorage = auseUserStorage;
    this.useCertificateStorage = auseCertificateStorage;
    this.acceptRevocationNonExistingEntry = aacceptRevocationNonExistingEntry;
    setCmpRaAuthSecret(acmpRaAuthSecret);
    this.keepExpiredCertsOnCRL = keepExpiredCertsOnCRL;
    this.authorityInformationAccess = aauthorityInformationAccess;
    this.certificateAiaDefaultCaIssuerUri = acertificateAiaDefaultCaIssuerUri;
    this.nameConstraintsPermitted = anameConstraintsPermitted;
    this.nameConstraintsExcluded = anameConstraintsExcluded;
    this.useNoConflictCertificateData = useNoConflictCertificateData;
    this.caSerialNumberOctetSize = acaSerialNumberOctetSize;
  }

  /**
   * Constructor that should be used when creating CA and retrieving CA info.
   * Please use the shorter form if you do not need to set all of the values.
   *
   * @param caid ID of the CA
   * @param defaultCertprofileId the id of default cetificate profile for
   *     certificates this CA issues
   * @param useNoConflictCertificateData should use NoConflictCertificate data
   *     table to write to
   * @param encodedValidity the validity of this CA as a human-readable string,
   *     e.g. 25y
   * @param catoken the CA token for this CA, containing e.g. a reference to the
   *     crypto token
   * @param description a text describing this CA
   * @param acaSerialNumberOctetSize serial number octet size for this CA
   * @param crlperiod the CRL validity period in ms
   * @param crlIssueInterval how often in ms the CRLs should be distributed,
   *     e.g. 3600000 will generate a new CRL every hour
   * @param crlOverlapTime the validity overlap in ms for a subsequent CRL, e.g.
   *     5000 will generate a CRL 5m before the previous CRL expires
   * @param deltacrlperiod how often Delta CRLs should be distributed
   * @param crlpublishers a collection of publisher IDs for this CA
   * @param keyValidators a collection of key validator IDs for this CA
   * @param auseauthoritykeyidentifier bool
   * @param aauthoritykeyidentifiercritical bool
   * @param ausecrlnumber bool
   * @param acrlnumbercritical bool
   * @param adefaultcrldistpoint the URI of the default CRL distribution point
   * @param adefaultcrlissuer Issuer
   * @param defaultocspservicelocator Locator
   * @param crlAuthorityInformationAccess Access info to CRLs
   * @param acertificateAiaDefaultCaIssuerUri Issuer URI
   * @param anameConstraintsPermitted a list of name constraints which should be
   *     permitted
   * @param anameConstraintsExcluded a list of name constraints which should be
   *     excluded
   * @param acadefinedfreshestcrl CRL
   * @param finishuser bool
   * @param extendedcaserviceinfos bool
   * @param auseUTF8PolicyText bool
   * @param approvals a map of approval profiles which should be used for
   *     different operations
   * @param ausePrintableStringSubjectDN bool
   * @param useLdapDnOrder biik
   * @param auseCrlDistributionPointOnCrl bool
   * @param acrlDistributionPointOnCrlCritical bool
   * @param includeInHealthCheck enable healthcheck for this CA
   * @param adoEnforceUniquePublicKeys bool
   * @param adoEnforceUniqueDistinguishedName bool
   * @param adoEnforceUniqueSubjectDNSerialnumber bool
   * @param auseCertReqHistory bool
   * @param auseUserStorage bool
   * @param auseCertificateStorage bool
   * @param aacceptRevocationNonExistingEntry bool
   * @param acmpRaAuthSecret bool
   * @param keepExpiredCertsOnCRL bool
   */
  public X509CAInfo(
      final int caid,
      final String encodedValidity,
      final CAToken catoken,
      final String description,
      final int acaSerialNumberOctetSize,
      final long crlperiod,
      final long crlIssueInterval,
      final long crlOverlapTime,
      final long deltacrlperiod,
      final Collection<Integer> crlpublishers,
      final Collection<Integer> keyValidators,
      final boolean auseauthoritykeyidentifier,
      final boolean aauthoritykeyidentifiercritical,
      final boolean ausecrlnumber,
      final boolean acrlnumbercritical,
      final String adefaultcrldistpoint,
      final String adefaultcrlissuer,
      final String defaultocspservicelocator,
      final List<String> crlAuthorityInformationAccess,
      final List<String> acertificateAiaDefaultCaIssuerUri,
      final List<String> anameConstraintsPermitted,
      final List<String> anameConstraintsExcluded,
      final String acadefinedfreshestcrl,
      final boolean finishuser,
      final Collection<ExtendedCAServiceInfo> extendedcaserviceinfos,
      final boolean auseUTF8PolicyText,
      final Map<ApprovalRequestType, Integer> approvals,
      final boolean ausePrintableStringSubjectDN,
      final boolean useLdapDnOrder,
      final boolean auseCrlDistributionPointOnCrl,
      final boolean acrlDistributionPointOnCrlCritical,
      final boolean includeInHealthCheck,
      final boolean adoEnforceUniquePublicKeys,
      final boolean adoEnforceUniqueDistinguishedName,
      final boolean adoEnforceUniqueSubjectDNSerialnumber,
      final boolean auseCertReqHistory,
      final boolean auseUserStorage,
      final boolean auseCertificateStorage,
      final boolean aacceptRevocationNonExistingEntry,
      final String acmpRaAuthSecret,
      final boolean keepExpiredCertsOnCRL,
      final int defaultCertprofileId,
      final boolean useNoConflictCertificateData) {
    this.caid = caid;
    this.encodedValidity = encodedValidity;
    this.catoken = catoken;
    this.description = description;
    this.caSerialNumberOctetSize = acaSerialNumberOctetSize;
    this.crlperiod = crlperiod;
    this.crlIssueInterval = crlIssueInterval;
    this.crlOverlapTime = crlOverlapTime;
    this.deltacrlperiod = deltacrlperiod;
    this.crlpublishers = crlpublishers;
    this.validators = keyValidators;
    this.useauthoritykeyidentifier = auseauthoritykeyidentifier;
    this.authoritykeyidentifiercritical = aauthoritykeyidentifiercritical;
    this.usecrlnumber = ausecrlnumber;
    this.crlnumbercritical = acrlnumbercritical;
    this.defaultcrldistpoint = adefaultcrldistpoint;
    this.defaultcrlissuer = adefaultcrlissuer;
    this.defaultocsplocator = defaultocspservicelocator;
    this.cadefinedfreshestcrl = acadefinedfreshestcrl;
    this.finishuser = finishuser;
    this.extendedcaserviceinfos = extendedcaserviceinfos;
    this.useUTF8PolicyText = auseUTF8PolicyText;
    setApprovals(approvals);
    this.usePrintableStringSubjectDN = ausePrintableStringSubjectDN;
    this.useLdapDNOrder = useLdapDnOrder;
    this.useCrlDistributionPointOnCrl = auseCrlDistributionPointOnCrl;
    this.crlDistributionPointOnCrlCritical = acrlDistributionPointOnCrlCritical;
    this.includeInHealthCheck = includeInHealthCheck;
    this.doEnforceUniquePublicKeys = adoEnforceUniquePublicKeys;
    this.doEnforceUniqueDistinguishedName = adoEnforceUniqueDistinguishedName;
    this.doEnforceUniqueSubjectDNSerialnumber =
        adoEnforceUniqueSubjectDNSerialnumber;
    this.useCertReqHistory = auseCertReqHistory;
    this.useUserStorage = auseUserStorage;
    this.useCertificateStorage = auseCertificateStorage;
    this.acceptRevocationNonExistingEntry = aacceptRevocationNonExistingEntry;
    setCmpRaAuthSecret(acmpRaAuthSecret);
    this.keepExpiredCertsOnCRL = keepExpiredCertsOnCRL;
    this.authorityInformationAccess = crlAuthorityInformationAccess;
    this.certificateAiaDefaultCaIssuerUri = acertificateAiaDefaultCaIssuerUri;
    this.nameConstraintsPermitted = anameConstraintsPermitted;
    this.nameConstraintsExcluded = anameConstraintsExcluded;
    this.defaultCertificateProfileId = defaultCertprofileId;
    this.useNoConflictCertificateData = useNoConflictCertificateData;
  }
  /** @return policies */
  public List<CertificatePolicy> getPolicies() {
    return this.policies;
  }

  /** @param aPolicies policies  */
  public void setPolicies(final List<CertificatePolicy> aPolicies) {
    this.policies = aPolicies;
  }

  /** @return boolean */
  public boolean getUseCRLNumber() {
    return usecrlnumber;
  }
  /** @param aUsecrlnumber boolean  */
  public void setUseCRLNumber(final boolean aUsecrlnumber) {
    this.usecrlnumber = aUsecrlnumber;
  }
  /** @return boolean */
  public boolean getCRLNumberCritical() {
    return crlnumbercritical;
  }

  /** @param aCrlnumbercritical boolean */
  public void setCRLNumberCritical(final boolean aCrlnumbercritical) {
    this.crlnumbercritical = aCrlnumbercritical;
  }

  /** @return boolean */
  public boolean getUseAuthorityKeyIdentifier() {
    return useauthoritykeyidentifier;
  }
  /** @param aUseauthoritykeyidentifier boolean */
  public void setUseAuthorityKeyIdentifier(
          final boolean aUseauthoritykeyidentifier) {
    this.useauthoritykeyidentifier = aUseauthoritykeyidentifier;
  }
  /** @return boolean */
  public boolean getAuthorityKeyIdentifierCritical() {
    return authoritykeyidentifiercritical;
  }
  /** @param aAuthoritykeyidentifiercritical boolean */
  public void setAuthorityKeyIdentifierCritical(
      final boolean aAuthoritykeyidentifiercritical) {
    this.authoritykeyidentifiercritical = aAuthoritykeyidentifiercritical;
  }

  /** @return dist */
  public String getDefaultCRLDistPoint() {
    return defaultcrldistpoint;
  }

  /** @param aDefaultCRLDistPoint dist */
  public void setDefaultCRLDistPoint(final String aDefaultCRLDistPoint) {
    this.defaultcrldistpoint = aDefaultCRLDistPoint;
  }

  /** @return issuer */
  public String getDefaultCRLIssuer() {
    return defaultcrlissuer;
  }

  /** @param aDefaultcrlissuer issuer */
  public void setDefaultCRLIssuer(final String aDefaultcrlissuer) {
    this.defaultcrlissuer = aDefaultcrlissuer;
  }

  /** @return locator */
  public String getDefaultOCSPServiceLocator() {
    return defaultocsplocator;
  }
 /** @param aDefaultocsplocator locator */
  public void setDefaultOCSPServiceLocator(final String aDefaultocsplocator) {
    this.defaultocsplocator = aDefaultocsplocator;
  }

  /** @return crl */
  public String getCADefinedFreshestCRL() {
    return this.cadefinedfreshestcrl;
  }

  /**@param cADefinedFreshestCRL CRL */
  public void setCADefinedFreshestCRL(final String cADefinedFreshestCRL) {
    this.cadefinedfreshestcrl = cADefinedFreshestCRL;
  }

  /** @return name */
  public String getSubjectAltName() {
    return subjectaltname;
  }

  /** @param aSubjectaltname name */
  public void setSubjectAltName(final String aSubjectaltname) {
    this.subjectaltname = aSubjectaltname;
  }

  /** @return boolean */
  public boolean getUseUTF8PolicyText() {
    return useUTF8PolicyText;
  }
  /** @param aUseUTF8PolicyText boolean */
  public void setUseUTF8PolicyText(final boolean aUseUTF8PolicyText) {
    this.useUTF8PolicyText = aUseUTF8PolicyText;
  }
  /** @return boolean */
  public boolean getUsePrintableStringSubjectDN() {
    return usePrintableStringSubjectDN;
  }

  /** @param aUsePrintableStringSubjectDN boolean  */
  public void setUsePrintableStringSubjectDN(
      final boolean aUsePrintableStringSubjectDN) {
    this.usePrintableStringSubjectDN = aUsePrintableStringSubjectDN;
  }

  /** @return boolean */
  public boolean getUseLdapDnOrder() {
    return useLdapDNOrder;
  }
  /** @param aUseLdapDNOrder boolean */
  public void setUseLdapDnOrder(final boolean aUseLdapDNOrder) {
    this.useLdapDNOrder = aUseLdapDNOrder;
  }

  /** @return boolean */
  public boolean getUseCrlDistributionPointOnCrl() {
    return this.useCrlDistributionPointOnCrl;
  }

  /** @param aUseCrlDistributionPointOnCrl boolean */
  public void setUseCrlDistributionPointOnCrl(
      final boolean aUseCrlDistributionPointOnCrl) {
    this.useCrlDistributionPointOnCrl = aUseCrlDistributionPointOnCrl;
  }

  /** @return boolean */
  public boolean getCrlDistributionPointOnCrlCritical() {
    return this.crlDistributionPointOnCrlCritical;
  }

  /** @param aCrlDistributionPointOnCrlCritical boolean */
  public void setCrlDistributionPointOnCrlCritical(
      final boolean aCrlDistributionPointOnCrlCritical) {
    this.crlDistributionPointOnCrlCritical = aCrlDistributionPointOnCrlCritical;
  }

  /** @return secret */
  public String getCmpRaAuthSecret() {
    return cmpRaAuthSecret;
  }

  /** @param aCmpRaAuthSecret cmpRaAuthSecret */
  public void setCmpRaAuthSecret(final String aCmpRaAuthSecret) {
    this.cmpRaAuthSecret = aCmpRaAuthSecret == null ? "" : aCmpRaAuthSecret;
  }

  /** @return list */
  public List<String> getAuthorityInformationAccess() {
    return authorityInformationAccess;
  }

  /** @param list list */
  public void setAuthorityInformationAccess(final List<String> list) {
    this.authorityInformationAccess = list;
  }

  /** @return the certificateAiaDefaultCaIssuerUri */
  public List<String> getCertificateAiaDefaultCaIssuerUri() {
    return certificateAiaDefaultCaIssuerUri;
  }

  /** @param list the certificateAiaDefaultCaIssuerUri to set */
  public void setCertificateAiaDefaultCaIssuerUri(final List<String> list) {
    this.certificateAiaDefaultCaIssuerUri = list;
  }

  /**
   * @return a list of encoded names of the permitted names in issued
   *     certificates
   */
  public List<String> getNameConstraintsPermitted() {
    return nameConstraintsPermitted;
  }

  /** @param encodedNames names */
  public void setNameConstraintsPermitted(final List<String> encodedNames) {
    nameConstraintsPermitted = encodedNames;
  }

  /**
   * @return a list of encoded names of the forbidden names in issued
   *     certificates
   */
  public List<String> getNameConstraintsExcluded() {
    return nameConstraintsExcluded;
  }

  /** @param encodedNames Names. */
  public void setNameConstraintsExcluded(final List<String> encodedNames) {
    nameConstraintsExcluded = encodedNames;
  }

  /**
   * @return what should be a String formatted URL pointing to an external CA's
   *     CDP.
   */
  public String getExternalCdp() {
    return externalCdp;
  }

  /**
   * Set what should be a String formatted URL pointing to an external CA's CDP.
   *
   * @param aExternalCdp CDP
   */
  public void setExternalCdp(final String aExternalCdp) {
    this.externalCdp = aExternalCdp;
  }

  /**
   * @return true if CA has undergone through name change at some renewal
   *     process, otherwise false.
   */
  public boolean getNameChanged() {
    return nameChanged;
  }

  /**
   * NameChanged attribute should only be set when X509CA is retrieved from DB.
   *
   * @param value new name
   */
  void setNameChanged(final boolean value) {
    nameChanged = value;
  }

  /** @return size. */
  public int getCaSerialNumberOctetSize() {
    return caSerialNumberOctetSize;
  }

  /** @param aCaSerialNumberOctetSize size */
  public void setCaSerialNumberOctetSize(final int aCaSerialNumberOctetSize) {
    this.caSerialNumberOctetSize = aCaSerialNumberOctetSize;
  }

  /** Factory. */
  public static class X509CAInfoBuilder {
    /** DN. */
    private String subjectDn;
    /** Name. */
    private String name;
    /** Status. */
    private int status;
    /** ID. */
    private int certificateProfileId;
    /** Validity. */
    private String encodedValidity;
    /** Signers. */
    private int signedBy;
    /** Certs. */
    private Collection<Certificate> certificateChain;
    /** Token. */
    private CAToken caToken;
    /** Time. */
    private Date updateTime = new Date();
    /** Name. */
    private String subjectAltName = "";
    /** ID. */
    private int defaultCertProfileId = 0;
    /** Boolean. */
    private boolean useNoConflictCertificateData = false;
    /** Time. */
    private Date expireTime = null;
    /** Type. */
    private int caType = CAInfo.CATYPE_X509;
    /** Description. */
    private String description = "";
    /** SN size. */
    private int caSerialNumberOctetSize = -1;
    /** Reason. */
    private int revocationReason = -1;
    /** Date. */
    private Date revocationDate = null;
    /** Policies. */
    private List<CertificatePolicy> policies = null;
    /** Period. */
    private long crlPeriod = 1 * SimpleTime.MILLISECONDS_PER_DAY;
    /** Interval. */
    private long crlIssueInterval = 0L;
    /** Overlap. */
    private long crlOverlapTime = 10 * SimpleTime.MILLISECONDS_PER_MINUTE;
    /** CRL change period. */
    private long deltaCrlPeriod = 0L;
    /** Publishers. */
    private Collection<Integer> crlPublishers = new ArrayList<Integer>();
    /** Validators. */
    private Collection<Integer> validators = new ArrayList<Integer>();
    /** Boolean. */
    private boolean useAuthorityKeyIdentifier = true;
    /** Boolean. */
    private boolean authorityKeyIdentifierCritical = false;
    /** Boolean. */
    private boolean useCrlNumber = true;
    /** Boolean. */
    private boolean crlNumberCritical = false;
    /** Distribution. */
    private String defaultCrlDistPoint = null;
    /** Issuer. */
    private String defaultCrlIssuer = null;
    /** Locator. */
    private String defaultOcspCerviceLocator = null;
    /** Access. */
    private List<String> authorityInformationAccess = null;
    /** URIs. */
    private List<String> certificateAiaDefaultCaIssuerUri = null;
    /** Constraints. */
    private List<String> nameConstraintsPermitted = null;
    /** Constraints. */
    private List<String> nameConstraintsExcluded = null;
    /** CRL. */
    private String caDefinedFreshestCrl = null;
    /** Boolean. */
    private boolean finishUser = true;
    /** Info. */
    private Collection<ExtendedCAServiceInfo> extendedCaServiceInfos =
        new ArrayList<ExtendedCAServiceInfo>();
    /** Boolean. */
    private boolean useUtf8PolicyText = false;
    /** Approvals. */
    private Map<ApprovalRequestType, Integer> approvals =
        new HashMap<ApprovalRequestType, Integer>();
    /** Boolean. */
    private boolean usePrintableStringSubjectDN = false;
    /** Boolean. */
    private boolean useLdapDnOrder = true;
    /** Boolean. */
    private boolean useCrlDistributionPointOnCrl = false;
    /** Boolean. */
    private boolean crlDistributionPointOnCrlCritical = false;
    /** Boolean. */
    private boolean includeInHealthCheck = true;
    /** Boolean. */
    private boolean doEnforceUniquePublicKeys = true;
    /** Boolean. */
    private boolean doEnforceUniqueDistinguishedName = true;
    /** Boolean. */
    private boolean doEnforceUniqueSubjectDNSerialnumber = false;
    /** Boolean. */
    private boolean useCertReqHistory = false;
    /** Boolean. */
    private boolean useUserStorage = true;
    /** Boolean. */
    private boolean useCertificateStorage = true;
    /** Boolean. */
    private boolean acceptRevocationNonExistingEntry = false;
    /** Secret. */
    private String cmpRaAuthSecret = null;
    /** Boolean. */
    private boolean keepExpiredCertsOnCRL = false;

    /**
     * @param aSubjectDn DN
     * @return builder
     */
    public X509CAInfoBuilder setSubjectDn(final String aSubjectDn) {
      this.subjectDn = aSubjectDn;
      return this;
    }

    /**
     * @param aName Name
     * @return builder
     */
    public X509CAInfoBuilder setName(final String aName) {
      this.name = aName;
      return this;
    }

    /**
     * @param aStatus status
     * @return builder
     */
    public X509CAInfoBuilder setStatus(final int aStatus) {
      this.status = aStatus;
      return this;
    }

    /**
     * @param aCertificateProfileId ID
     * @return builder
     */
    public X509CAInfoBuilder setCertificateProfileId(
            final int aCertificateProfileId) {
      this.certificateProfileId = aCertificateProfileId;
      return this;
    }

    /**
     * @param aEncodedValidity validity
     * @return builder
     */
    public X509CAInfoBuilder setEncodedValidity(final String aEncodedValidity) {
      this.encodedValidity = aEncodedValidity;
      return this;
    }

    /**
     * @param aSignedBy int
     * @return builder
     */
    public X509CAInfoBuilder setSignedBy(final int aSignedBy) {
      this.signedBy = aSignedBy;
      return this;
    }

    /**
     * @param aCertificateChain chain
     * @return builder
     */
    public X509CAInfoBuilder setCertificateChain(
        final Collection<Certificate> aCertificateChain) {
      this.certificateChain = aCertificateChain;
      return this;
    }

    /**
     * @param aToken token
     * @return builder
     */
    public X509CAInfoBuilder setCaToken(final CAToken aToken) {
      this.caToken = aToken;
      return this;
    }

    /**
     * @param aUpdateTime time
     * @return builder
     */
    public X509CAInfoBuilder setUpdateTime(final Date aUpdateTime) {
      this.updateTime = aUpdateTime;
      return this;
    }

    /**
     * @param aSubjectAltName Name
     * @return builder
     */
    public X509CAInfoBuilder setSubjectAltName(final String aSubjectAltName) {
      this.subjectAltName = aSubjectAltName;
      return this;
    }

    /**
     * @param aDefaultCertProfileId ID
     * @return builder
     */
    public X509CAInfoBuilder setDefaultCertProfileId(
            final int aDefaultCertProfileId) {
      this.defaultCertProfileId = aDefaultCertProfileId;
      return this;
    }

    /**
     * @param aUseNoConflictCertificateData boolean
     * @return builder
     */
    public X509CAInfoBuilder setUseNoConflictCertificateData(
        final boolean aUseNoConflictCertificateData) {
      this.useNoConflictCertificateData = aUseNoConflictCertificateData;
      return this;
    }

    /**
     * @param aExpireTime Time
     * @return builder
     */
    public X509CAInfoBuilder setExpireTime(final Date aExpireTime) {
      this.expireTime = aExpireTime;
      return this;
    }

    /**
     * @param aType type
     * @return builder
     */
    public X509CAInfoBuilder setCaType(final int aType) {
      this.caType = aType;
      return this;
    }

    /**
     * @param aDescription desc
     * @return builder
     */
    public X509CAInfoBuilder setDescription(final String aDescription) {
      this.description = aDescription;
      return this;
    }
    /**
     * @param aRevocationReason Reason
     * @return builder
     */
    public X509CAInfoBuilder setRevocationReason(final int aRevocationReason) {
      this.revocationReason = aRevocationReason;
      return this;
    }
    /**
     * @param aRevocationDate Date
     * @return builder
     */
    public X509CAInfoBuilder setRevocationDate(final Date aRevocationDate) {
      this.revocationDate = aRevocationDate;
      return this;
    }

    /**
     * @param aPolicies Policies
     * @return builder
     */
    public X509CAInfoBuilder setPolicies(
            final List<CertificatePolicy> aPolicies) {
      this.policies = aPolicies;
      return this;
    }

    /**
     * @param aCrlPeriod Period
     * @return builder
     */
    public X509CAInfoBuilder setCrlPeriod(final long aCrlPeriod) {
      this.crlPeriod = aCrlPeriod;
      return this;
    }

    /**
     * @param aCrlIssueInterval Interval
     * @return builder
     */
    public X509CAInfoBuilder setCrlIssueInterval(final long aCrlIssueInterval) {
      this.crlIssueInterval = aCrlIssueInterval;
      return this;
    }

    /**
     * @param aCrlOverlapTime Time
     * @return builder
     */
    public X509CAInfoBuilder setCrlOverlapTime(final long aCrlOverlapTime) {
      this.crlOverlapTime = aCrlOverlapTime;
      return this;
    }

    /**
     * @param aDeltaCrlPeriod Period
     * @return builder
     */
    public X509CAInfoBuilder setDeltaCrlPeriod(final long aDeltaCrlPeriod) {
      this.deltaCrlPeriod = aDeltaCrlPeriod;
      return this;
    }

    /**
     * @param aCrlPublishers Publishers
     * @return builder
     */
    public X509CAInfoBuilder setCrlPublishers(
        final Collection<Integer> aCrlPublishers) {
      this.crlPublishers = aCrlPublishers;
      return this;
    }

    /**
     * @param aValidators validators
     * @return builder
     */
    public X509CAInfoBuilder setValidators(
            final Collection<Integer> aValidators) {
      this.validators = aValidators;
      return this;
    }

    /**
     * @param aUseAuthorityKeyIdentifier booleam
     * @return builder
     */
    public X509CAInfoBuilder setUseAuthorityKeyIdentifier(
        final boolean aUseAuthorityKeyIdentifier) {
      this.useAuthorityKeyIdentifier = aUseAuthorityKeyIdentifier;
      return this;
    }

    /**
     * @param aAuthorityKeyIdentifierCritical ID
     * @return builder
     */
    public X509CAInfoBuilder setAuthorityKeyIdentifierCritical(
        final boolean aAuthorityKeyIdentifierCritical) {
      this.authorityKeyIdentifierCritical = aAuthorityKeyIdentifierCritical;
      return this;
    }

    /**
     * @param aUseCrlNumber boolean
     * @return builder
     */
    public X509CAInfoBuilder setUseCrlNumber(final boolean aUseCrlNumber) {
      this.useCrlNumber = aUseCrlNumber;
      return this;
    }

    /**
     * @param aCrlNumberCritical Number
     * @return Builder
     */
    public X509CAInfoBuilder setCrlNumberCritical(
            final boolean aCrlNumberCritical) {
      this.crlNumberCritical = aCrlNumberCritical;
      return this;
    }

    /**
     * @param aDefaultCrlDistPoint Distribution
     * @return Builder
     */
    public X509CAInfoBuilder setDefaultCrlDistPoint(
        final String aDefaultCrlDistPoint) {
      this.defaultCrlDistPoint = aDefaultCrlDistPoint;
      return this;
    }

    /**
     * @param aDefaultCrlIssuer CRL issuer
     * @return Builder
     */
    public X509CAInfoBuilder setDefaultCrlIssuer(
            final String aDefaultCrlIssuer) {
      this.defaultCrlIssuer = aDefaultCrlIssuer;
      return this;
    }

    /**
     * @param aDefaultOcspCerviceLocator Locator
     * @return Builder
     */
    public X509CAInfoBuilder setDefaultOcspCerviceLocator(
        final String aDefaultOcspCerviceLocator) {
      this.defaultOcspCerviceLocator = aDefaultOcspCerviceLocator;
      return this;
    }

    /**
     * @param aAuthorityInformationAccess Access
     * @return Builder
     */
    public X509CAInfoBuilder setAuthorityInformationAccess(
        final List<String> aAuthorityInformationAccess) {
      this.authorityInformationAccess = aAuthorityInformationAccess;
      return this;
    }

    /**
     * @param aCertificateAiaDefaultCaIssuerUri URIs
     * @return Builder
     */
    public X509CAInfoBuilder setCertificateAiaDefaultCaIssuerUri(
        final List<String> aCertificateAiaDefaultCaIssuerUri) {
      this.certificateAiaDefaultCaIssuerUri = aCertificateAiaDefaultCaIssuerUri;
      return this;
    }

    /**
     * @param aNameConstraintsPermitted Constraints
     * @return builder
     */
    public X509CAInfoBuilder setNameConstraintsPermitted(
        final List<String> aNameConstraintsPermitted) {
      this.nameConstraintsPermitted = aNameConstraintsPermitted;
      return this;
    }

    /**
     * @param aNameConstraintsExcluded Constraints
     * @return builder
     */
    public X509CAInfoBuilder setNameConstraintsExcluded(
        final List<String> aNameConstraintsExcluded) {
      this.nameConstraintsExcluded = aNameConstraintsExcluded;
      return this;
    }

    /**
     * @param aCaDefinedFreshestCrl CRL
     * @return Builder
     */
    public X509CAInfoBuilder setCaDefinedFreshestCrl(
        final String aCaDefinedFreshestCrl) {
      this.caDefinedFreshestCrl = aCaDefinedFreshestCrl;
      return this;
    }

    /**
     * @param aFinishUser boolean
     * @return builder
     */
    public X509CAInfoBuilder setFinishUser(final boolean aFinishUser) {
      this.finishUser = aFinishUser;
      return this;
    }

    /**
     * @param aExtendedCaServiceInfos Infos
     * @return Builder
     */
    public X509CAInfoBuilder setExtendedCaServiceInfos(
       final Collection<ExtendedCAServiceInfo> aExtendedCaServiceInfos) {
      this.extendedCaServiceInfos = aExtendedCaServiceInfos;
      return this;
    }

    /**
     * @param aUseUtf8PolicyText boolean
     * @return builder
     */
    public X509CAInfoBuilder setUseUtf8PolicyText(
            final boolean aUseUtf8PolicyText) {
      this.useUtf8PolicyText = aUseUtf8PolicyText;
      return this;
    }

    /**
     * @param aApprovals approvals
     * @return builder
     */
    public X509CAInfoBuilder setApprovals(
        final Map<ApprovalRequestType, Integer> aApprovals) {
      this.approvals = aApprovals;
      return this;
    }

    /**
     * @param aUsePrintableStringSubjectDN boolean
     * @return builder
     */
    public X509CAInfoBuilder setUsePrintableStringSubjectDN(
        final boolean aUsePrintableStringSubjectDN) {
      this.usePrintableStringSubjectDN = aUsePrintableStringSubjectDN;
      return this;
    }

    /**
     * @param aUseLdapDnOrder boolean
     * @return builder
     */
    public X509CAInfoBuilder setUseLdapDnOrder(final boolean aUseLdapDnOrder) {
      this.useLdapDnOrder = aUseLdapDnOrder;
      return this;
    }

    /**
     * @param aUseCrlDistributionPointOnCrl boolean
     * @return builder
     */
    public X509CAInfoBuilder setUseCrlDistributionPointOnCrl(
        final boolean aUseCrlDistributionPointOnCrl) {
      this.useCrlDistributionPointOnCrl = aUseCrlDistributionPointOnCrl;
      return this;
    }

    /**
     * @param aCrlDistributionPointOnCrlCritical boolean
     * @return builder
     */
    public X509CAInfoBuilder setCrlDistributionPointOnCrlCritical(
        final boolean aCrlDistributionPointOnCrlCritical) {
      this.crlDistributionPointOnCrlCritical =
          aCrlDistributionPointOnCrlCritical;
      return this;
    }

    /**
     * @param aIncludeInHealthCheck boolean
     * @return builder
     */
    public X509CAInfoBuilder setIncludeInHealthCheck(
        final boolean aIncludeInHealthCheck) {
      this.includeInHealthCheck = aIncludeInHealthCheck;
      return this;
    }

    /**
     * @param aDoEnforceUniquePublicKeys boolean
     * @return builder
     */
    public X509CAInfoBuilder setDoEnforceUniquePublicKeys(
        final boolean aDoEnforceUniquePublicKeys) {
      this.doEnforceUniquePublicKeys = aDoEnforceUniquePublicKeys;
      return this;
    }

    /**
     * @param aDoEnforceUniqueDistinguishedName boolean
     * @return builder
     */
    public X509CAInfoBuilder setDoEnforceUniqueDistinguishedName(
        final boolean aDoEnforceUniqueDistinguishedName) {
      this.doEnforceUniqueDistinguishedName = aDoEnforceUniqueDistinguishedName;
      return this;
    }

    /**
     * @param aDoEnforceUniqueSubjectDNSerialnumber boolean
     * @return builder
     */
    public X509CAInfoBuilder setDoEnforceUniqueSubjectDNSerialnumber(
        final boolean aDoEnforceUniqueSubjectDNSerialnumber) {
      this.doEnforceUniqueSubjectDNSerialnumber =
          aDoEnforceUniqueSubjectDNSerialnumber;
      return this;
    }

    /**
     * @param aUseCertReqHistory boolean
     * @return builder
     */
    public X509CAInfoBuilder setUseCertReqHistory(
            final boolean aUseCertReqHistory) {
      this.useCertReqHistory = aUseCertReqHistory;
      return this;
    }

    /**
     * @param aUseUserStorage boolean
     * @return builder
     */
    public X509CAInfoBuilder setUseUserStorage(final boolean aUseUserStorage) {
      this.useUserStorage = aUseUserStorage;
      return this;
    }

    /**
     * @param aUseCertificateStorage boolean
     * @return builder
     */
    public X509CAInfoBuilder setUseCertificateStorage(
        final boolean aUseCertificateStorage) {
      this.useCertificateStorage = aUseCertificateStorage;
      return this;
    }

    /**
     * @param aAcceptRevocationNonExistingEntry boolean
     * @return Builder
     */
    public X509CAInfoBuilder setAcceptRevocationNonExistingEntry(
        final boolean aAcceptRevocationNonExistingEntry) {
      this.acceptRevocationNonExistingEntry = aAcceptRevocationNonExistingEntry;
      return this;
    }

    /**
     * @param caCmpRaAuthSecret Secret
     * @return Builder
     */
    public X509CAInfoBuilder setCmpRaAuthSecret(
            final String caCmpRaAuthSecret) {
      this.cmpRaAuthSecret = caCmpRaAuthSecret;
      return this;
    }

    /**
     * @param aKeepExpiredCertsOnCRL Boolean
     * @return Builder
     */
    public X509CAInfoBuilder setKeepExpiredCertsOnCRL(
        final boolean aKeepExpiredCertsOnCRL) {
      this.keepExpiredCertsOnCRL = aKeepExpiredCertsOnCRL;
      return this;
    }
    /**
     * @param aCaSerialNumberOctetSize SN size
     * @return Builder
     */
    public X509CAInfoBuilder setCaSerialNumberOctetSize(
        final int aCaSerialNumberOctetSize) {
      this.caSerialNumberOctetSize = aCaSerialNumberOctetSize;
      return this;
    }

    /** Build.
     * @return X509CAInfo
     *  */
    public X509CAInfo build() {
      return new X509CAInfo(
          subjectDn,
          name,
          status,
          updateTime,
          subjectAltName,
          certificateProfileId,
          defaultCertProfileId,
          useNoConflictCertificateData,
          encodedValidity,
          expireTime,
          caType,
          signedBy,
          certificateChain,
          caToken,
          description,
          caSerialNumberOctetSize,
          revocationReason,
          revocationDate,
          policies,
          crlPeriod,
          crlIssueInterval,
          crlOverlapTime,
          deltaCrlPeriod,
          crlPublishers,
          validators,
          useAuthorityKeyIdentifier,
          authorityKeyIdentifierCritical,
          useCrlNumber,
          crlNumberCritical,
          defaultCrlDistPoint,
          defaultCrlIssuer,
          defaultOcspCerviceLocator,
          authorityInformationAccess,
          certificateAiaDefaultCaIssuerUri,
          nameConstraintsPermitted,
          nameConstraintsExcluded,
          caDefinedFreshestCrl,
          finishUser,
          extendedCaServiceInfos,
          useUtf8PolicyText,
          approvals,
          usePrintableStringSubjectDN,
          useLdapDnOrder,
          useCrlDistributionPointOnCrl,
          crlDistributionPointOnCrlCritical,
          includeInHealthCheck,
          doEnforceUniquePublicKeys,
          doEnforceUniqueDistinguishedName,
          doEnforceUniqueSubjectDNSerialnumber,
          useCertReqHistory,
          useUserStorage,
          useCertificateStorage,
          acceptRevocationNonExistingEntry,
          cmpRaAuthSecret,
          keepExpiredCertsOnCRL);
    }
  }
}
