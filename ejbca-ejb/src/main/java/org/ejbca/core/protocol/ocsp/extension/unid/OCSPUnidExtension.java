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

package org.ejbca.core.protocol.ocsp.extension.unid;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ocsp.extension.OCSPExtension;
import org.cesecore.certificates.ocsp.extension.OCSPExtensionType;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingTrustEntry;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.unidfnr.UnidfnrSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * ASN.1 OCSP extension used to map a UNID to a Fnr, OID for this extension is
 * 2.16.578.1.16.3.2.
 *
 * @version $Id: OCSPUnidExtension.java 29359 2018-06-26 13:55:38Z mikekushner $
 */
public class OCSPUnidExtension implements OCSPExtension {

      /** param. */
  public static final String OCSP_UNID_OID = "2.16.578.1.16.3.2";
  /** param. */
  public static final String OCSP_UNID_NAME = "UnId Fnr";

  /** Logger. */
  private static final Logger LOG = Logger.getLogger(OCSPUnidExtension.class);
  /** Internal localization of logs and errors. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();

  /** param. */
  private CaSessionLocal caSession;
  /** param. */
  private UnidfnrSessionLocal unidfnrSession;

  /** param. */
  private int errCode = UnidFnrOCSPExtensionCode.ERROR_NO_ERROR.getValue();

  @Override
  public String getOid() {
    return OCSP_UNID_OID;
  }

  @Override
  public String getName() {
    return OCSP_UNID_NAME;
  }

  @Override
  public Set<OCSPExtensionType> getExtensionType() {
    return EnumSet.of(OCSPExtensionType.RESPONSE);
  }

  @Override
  public void init() {
    // Nothings need to be done here
  }

  @Override
  public Map<ASN1ObjectIdentifier, Extension> process(
      final X509Certificate[] requestCertificates,
      final String remoteAddress,
      final String remoteHost,
      final X509Certificate cert,
      final CertificateStatus status,
      final InternalKeyBinding internalKeyBinding) {

    String serialNumber = null;
    String fnr = null;

    // Check authorization first
    if (!checkAuthorization(
        requestCertificates,
        remoteAddress,
        remoteHost,
        internalKeyBinding.getTrustedCertificateReferences())) {
      errCode = UnidFnrOCSPExtensionCode.ERROR_UNAUTHORIZED.getValue();
      return null;
    }
    // If the certificate is revoked, we must not return an FNR
    if (status != null) {
      errCode = UnidFnrOCSPExtensionCode.ERROR_CERT_REVOKED.getValue();
      return null;
    }

    // The Unid is in the DN component serialNumber
    serialNumber = CertTools.getPartFromDN(cert.getSubjectDN().getName(), "SN");
    if (serialNumber != null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Found serialNumber: " + serialNumber);
      }
      String iMsg =
          INTRES.getLocalizedMessage(
              "ocsp.receivedunidreq", remoteAddress, remoteHost, serialNumber);
      LOG.info(iMsg);

      // Make sure unidfnrSession is loaded properly in all environments before
      // using it.
      if (unidfnrSession == null) {
        unidfnrSession = new EjbLocalHelper().getUnidfnrSession();
      }
      fnr = unidfnrSession.fetchUnidFnrData(serialNumber);
    } else {
      String errMsg =
          INTRES.getLocalizedMessage(
              "ocsp.errorunidnosnindn", cert.getSubjectDN().getName());
      LOG.error(errMsg);
      errCode = UnidFnrOCSPExtensionCode.ERROR_NO_SERIAL_IN_DN.getValue();
      return null;
    }

    if (fnr == null) {
      String errMsg =
          INTRES.getLocalizedMessage("ocsp.errorunidnosnmapping", serialNumber);
      LOG.error(errMsg);
      errCode = UnidFnrOCSPExtensionCode.ERROR_NO_FNR_MAPPING.getValue();
      return null;
    }

    String successMsg =
        INTRES.getLocalizedMessage(
            "ocsp.returnedunidresponse",
            remoteAddress,
            remoteHost,
            serialNumber);
    LOG.info(successMsg);

    return generateUnidFnrOCSPResponce(fnr);
  }

  /**
   * Returns the last error that occurred during process(), when process returns
   * null.
   *
   * @return error code as defined by implementing class
   */
  @Override
  public int getLastErrorCode() {
    return errCode;
  }

  private boolean checkAuthorization(
      final X509Certificate[] certificates,
      final String remoteAddress,
      final String remoteHost,
      final List<InternalKeyBindingTrustEntry> bindingTrustEntries) {
    if (certificates == null) {
      String errMsg =
          INTRES.getLocalizedMessage(
              "ocsp.errornoclientauth", remoteAddress, remoteHost);
      LOG.error(errMsg);
      return false;
    }
    // The certificate of the entity is nr 0
    X509Certificate cert = certificates[0];
    if (cert == null) {
      String errMsg =
          INTRES.getLocalizedMessage(
              "ocsp.errornoclientauth", remoteAddress, remoteHost);
      LOG.error(errMsg);
      return false;
    }

    // Check if the certificate is authorized to access the Fnr
    boolean serialExists = false;
    final String issuerDN = CertTools.getIssuerDN(cert);

    // Make sure caSession is loaded properly in all environments before using
    // it.
    if (caSession == null) {
      caSession = new EjbLocalHelper().getCaSession();
    }

    final CAInfo caInfo = caSession.getCAInfoInternal(issuerDN.hashCode());

    for (final InternalKeyBindingTrustEntry bindingTrustEntry
        : bindingTrustEntries) {
      // Match
      final BigInteger trustEntrySerial =
          bindingTrustEntry.fetchCertificateSerialNumber();
      if ((trustEntrySerial == null
              || trustEntrySerial.equals(cert.getSerialNumber()))
          && caInfo.getCAId() == bindingTrustEntry.getCaId()) {
        serialExists = true;
      }
    }

    if (serialExists) {
      // If we found in the hashmap the same key with issuer and serialnumber,
      // we know we got it.
      // Just verify it as well to be damn sure
      final Certificate cacert = caInfo.getCertificateChain().get(0);
      try {
        cert.verify(cacert.getPublicKey());
      } catch (Exception e) {
        String errMsg = INTRES.getLocalizedMessage("ocsp.errorverifycert");
        LOG.error(errMsg, e);
        return false;
      }
      // If verify was successful we know if was good!
      return true;
    }

    String errMsg =
        INTRES.getLocalizedMessage(
            "ocsp.erroruntrustedclientauth", remoteAddress, remoteHost);
    LOG.error(errMsg);
    return false;
  }

  private Map<ASN1ObjectIdentifier, Extension> generateUnidFnrOCSPResponce(
      final String fnr) {
    FnrFromUnidExtension ext = new FnrFromUnidExtension(fnr);
    HashMap<ASN1ObjectIdentifier, Extension> unidOCSPResponse =
        new HashMap<ASN1ObjectIdentifier, Extension>();
    try {
      unidOCSPResponse.put(
          FnrFromUnidExtension.FNR_FROM_UNID_OID,
          new Extension(
              FnrFromUnidExtension.FNR_FROM_UNID_OID,
              false,
              new DEROctetString(ext)));
    } catch (IOException e) {
      throw new IllegalStateException("Unexpected IOException caught.", e);
    }
    return unidOCSPResponse;
  }
}
