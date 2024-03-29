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
package org.cesecore.certificates.ca;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.ServiceLoader;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.X509CRLHolder;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceTypeConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.config.CesecoreConfigurationHelper;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.CryptoToken;

/**
 * Base class for CVC CAs. Holds data specific for Certificate and CRL
 * generation according to the CVC (Card Verifiable Certificate) standards,
 * which are not real standards. There can be many different implementations of
 * CVC CA which are quite different, for example EU EAC electronic passports,
 * Tachographs and eIDs.
 *
 * @version $Id: CvcCA.java 30618 2018-11-26 07:27:19Z samuellb $
 */
public abstract class CvcCA extends CA implements Serializable {

  private static final long serialVersionUID = 3L;
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(CvcCA.class);

  /** Internal localization of logs and errors. */
  private static final InternalResources INTRES =
      InternalResources.getInstance();

  /**
   * Version of this class, if this is increased the upgrade() method will be
   * called automatically.
   */
  public static final float LATEST_VERSION = 4;

  /**
   * Creates a new instance of CA, this constructor should be used when a new CA
   * is created.
   *
   * @param cainfo info
   */
  public void init(final CVCCAInfo cainfo) {
    super.init(cainfo);
    data.put(CA.CATYPE, Integer.valueOf(CAInfo.CATYPE_CVC));
    data.put(VERSION, Float.valueOf(LATEST_VERSION));
  }

  /**
   *
   * @param cainfo Info
   * @return Instance
   */
  public static CvcCA getInstance(final CVCCAInfo cainfo) {
    // For future: Type here should be extracted from cainfo to select between
    // different implementations
    CvcCA ret = (CvcCA) createCAImpl("EAC");
    if (ret != null) {
      ret.init(cainfo);
    }
    return ret;
  }

  /** @param data Data
 * @param caId ID
 * @param subjectDN DN
 * @param name Name
 * @param status Status
 * @param updateTime Time
 * @param expireTime Time
 * @return singleton instance. */
  public static CvcCA getInstance(
      final HashMap<Object, Object> data,
      final int caId,
      final String subjectDN,
      final String name,
      final int status,
      final Date updateTime,
      final Date expireTime) {
    // For future: Type here should be extracted from data to select between
    // different implementations
    CvcCA ret = (CvcCA) createCAImpl("EAC");
    if (ret != null) {
      ret.init(data, caId, subjectDN, name, status, updateTime, expireTime);
    }
    return ret;
  }

  /** @return Class Loader */
  public static ServiceLoader<? extends CvcPlugin> getImplementationClasses() {
    ServiceLoader<? extends CvcPlugin> serviceLoader =
        ServiceLoader.load(CvcPlugin.class);
    return serviceLoader;
  }

  private static CvcPlugin createCAImpl(final String type) {
    // type can be used to differentiate between different types of CVC CA
    // implementations as there
    // can be several different types of CVC: EAC, Tachograph, eID etc.
    ServiceLoader<? extends CvcPlugin> serviceLoader =
        getImplementationClasses();
    for (CvcPlugin cvcPlugin : serviceLoader) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "ServiceLoader found CvcPlugin implementation: "
                + cvcPlugin.getCvcType());
      }
      if (type.equals(cvcPlugin.getCvcType())) {
        return cvcPlugin;
      }
    }
    // No implementation found, it is probably an Enterprise only feature
    LOG.info("CVC CA is not available in this version of EJBCA.");
    return null;
  }

  /**
   * Constructor used when retrieving existing CVCCA from database.
   *
   * @param data data
   * @param caId ID
   * @param subjectDN DN
   * @param name name
   * @param status status
   * @param updateTime Update time
   * @param expireTime expiry
   */
  @SuppressWarnings("deprecation")
  public void init(
      final HashMap<Object, Object> data,
      final int caId,
      final String subjectDN,
      final String name,
      final int status,
      final Date updateTime,
      final Date expireTime) {
    super.init(data);
    setExpireTime(expireTime);
    final List<ExtendedCAServiceInfo> externalcaserviceinfos =
        new ArrayList<>();
    for (final Integer externalCAServiceType : getExternalCAServiceTypes()) {
      // Type was removed in 6.0.0. It is removed from the database in the
      // upgrade method in this class, but it needs to be ignored
      // for instantiation.
      if (externalCAServiceType
          != ExtendedCAServiceTypeConstants.TYPE_OCSPEXTENDEDSERVICE) {
        final ExtendedCAServiceInfo info =
            this.getExtendedCAServiceInfo(externalCAServiceType.intValue());
        if (info != null) {
          externalcaserviceinfos.add(info);
        }
      }
    }

    final CVCCAInfo info =
        new CVCCAInfo(
            subjectDN,
            name,
            status,
            updateTime,
            getCertificateProfileId(),
            getDefaultCertificateProfileId(),
            getEncodedValidity(),
            getExpireTime(),
            getCAType(),
            getSignedBy(),
            getCertificateChain(),
            getCAToken(),
            getDescription(),
            getRevocationReason(),
            getRevocationDate(),
            getCRLPeriod(),
            getCRLIssueInterval(),
            getCRLOverlapTime(),
            getDeltaCRLPeriod(),
            getCRLPublishers(),
            getValidators(),
            getFinishUser(),
            externalcaserviceinfos,
            getApprovals(),
            getIncludeInHealthCheck(),
            isDoEnforceUniquePublicKeys(),
            isDoEnforceUniqueDistinguishedName(),
            isDoEnforceUniqueSubjectDNSerialnumber(),
            isUseCertReqHistory(),
            isUseUserStorage(),
            isUseCertificateStorage(),
            isAcceptRevocationNonExistingEntry());
    // These to settings were deprecated in 6.8.0, but are still set for upgrade
    // reasons
    info.setApprovalProfile(getApprovalProfile());
    info.setApprovalSettings(getApprovalSettings());
    super.setCAInfo(info);
    setCAId(caId);
  }

  /** @return CVC type. */
  public abstract String getCvcType();

  @Override
  public byte[] createPKCS7(
      final CryptoToken cryptoToken,
      final X509Certificate cert, final boolean includeChain) {
    LOG.info(INTRES.getLocalizedMessage("cvc.info.nocvcpkcs7"));
    return null;
  }

  @Override
  public byte[] createPKCS7Rollover(final CryptoToken cryptoToken) {
    LOG.info(INTRES.getLocalizedMessage("cvc.info.nocvcpkcs7"));
    return null;
  }

  @Override
  public X509CRLHolder generateCRL(
      final CryptoToken cryptoToken,
      final Collection<RevokedCertInfo> certs,
      final int crlnumber) {
    String msg = INTRES.getLocalizedMessage("createcrl.nocrlcreate", "CVC");
    LOG.info(msg);
    return null;
  }

  @Override
  public X509CRLHolder generateDeltaCRL(
      final CryptoToken cryptoToken,
      final Collection<RevokedCertInfo> certs,
      final int crlnumber,
      final int basecrlnumber) {
    String msg = INTRES.getLocalizedMessage("createcrl.nocrlcreate", "CVC");
    LOG.info(msg);
    return null;
  }

  /** Implementation of UpgradableDataHashMap function getLatestVersion. */
  @Override
  public float getLatestVersion() {
    return LATEST_VERSION;
  }

  /** Implementation of UpgradableDataHashMap function upgrade. */
  @SuppressWarnings("deprecation")
  @Override
  public void upgrade() {
    if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
      // New version of the class, upgrade
      LOG.info("Upgrading CVCCA with version " + getVersion());

      // Put upgrade code here...

      // v1->v2 is only an upgrade in order to upgrade CA token
      // v2->v3 is a upgrade of X509CA that has to be adjusted here too, due to
      // the common heritage
      if (data.get(CRLPERIOD) instanceof Integer) {
        setCRLPeriod(0L);
      }
      if (data.get(CRLISSUEINTERVAL) instanceof Integer) {
        setCRLIssueInterval(0L);
      }
      if (data.get(CRLOVERLAPTIME) instanceof Integer) {
        setCRLOverlapTime(0L);
      }
      if (data.get(DELTACRLPERIOD) instanceof Integer) {
        setDeltaCRLPeriod(0L);
      }

      // v4.
      // 'encodedValidity' MUST set to "" (Empty String) here. The
      // initialization is done during post-upgrade of EJBCA 6.6.1.
      if (null == data.get(ENCODED_VALIDITY) && null != data.get(VALIDITY)) {
        setEncodedValidity(getEncodedValidity());
      }

      data.put(VERSION, new Float(LATEST_VERSION));
    }
  }

  /**
   * Method to upgrade new (or existing external caservices) This method needs
   * to be called outside the regular upgrade since the CA isn't instantiated in
   * the regular upgrade.
   */
  @Override
  @SuppressWarnings("deprecation")
  public boolean upgradeExtendedCAServices() {
    boolean retval = false;
    Collection<Integer> externalServiceTypes = getExternalCAServiceTypes();
    if (!CesecoreConfigurationHelper.getCaKeepOcspExtendedService()
        && externalServiceTypes.contains(
            ExtendedCAServiceTypeConstants.TYPE_OCSPEXTENDEDSERVICE)) {
      // This type has been removed, so remove it from any CAs it's been added
      // to as well.
      externalServiceTypes.remove(
          ExtendedCAServiceTypeConstants.TYPE_OCSPEXTENDEDSERVICE);
      data.put(EXTENDEDCASERVICES, externalServiceTypes);
      retval = true;
    }
    return retval;
  }

  @Override
  public byte[] decryptData(
      final CryptoToken cryptoToken, final byte[] data,
      final int cAKeyPurpose) {
    throw new IllegalArgumentException(
        "decryptData not implemented for CVC CA");
  }

  @Override
  public byte[] encryptData(
      final CryptoToken cryptoToken, final byte[] data, final int keyPurpose) {
    throw new IllegalArgumentException(
        "encryptData not implemented for CVC CA");
  }
}
