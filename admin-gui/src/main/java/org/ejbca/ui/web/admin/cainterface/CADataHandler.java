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

package org.ejbca.ui.web.admin.cainterface;

import java.io.ByteArrayInputStream;
import java.io.Serializable;
import java.security.KeyStore;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.validation.KeyValidatorSessionLocal;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleDataSessionLocal;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberDataSessionLocal;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.BaseSigningCAServiceInfo;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;

/**
 * A class help administrating CAs.
 *
 * @version $Id: CADataHandler.java 27816 2018-01-09 16:19:36Z samuellb $
 */
public class CADataHandler implements Serializable {

  private static final long serialVersionUID = 2132603037548273013L;

  /** Param. */
  private static final Logger LOG = Logger.getLogger(CADataHandler.class);

  /** Param. */
  private final AuthenticationToken administrator;

  /** Param. */
  private final RoleDataSessionLocal roleDataSession;
  /** Param. */
  private final RoleMemberDataSessionLocal roleMemberDataSession;
  /** Param. */
  private final CAAdminSessionLocal caadminsession;
  /** Param. */
  private final CaSessionLocal caSession;
  /** Param. */
  private final CertificateProfileSession certificateProfileSession;
  /** Param. */
  private final EndEntityProfileSession endEntityProfileSession;
  /** Param. */
  private final EndEntityManagementSessionLocal endEntitySession;
  /** Param. */
  private final KeyValidatorSessionLocal keyValidatorSession;
  /** Param. */
  private final PublisherSessionLocal publisherSession;

  /** Param. */
  private final EjbcaWebBean ejbcawebbean;

  /**
   * Creates a new instance of CADataHandler.
   *
   * @param authenticationToken Token
   * @param ejb EJB
   * @param anejbcawebbean Bean
   */
  public CADataHandler(
      final AuthenticationToken authenticationToken,
      final EjbLocalHelper ejb,
      final EjbcaWebBean anejbcawebbean) {
    this.roleDataSession = ejb.getRoleDataSession();
    this.roleMemberDataSession = ejb.getRoleMemberDataSession();
    this.caadminsession = ejb.getCaAdminSession();
    this.caSession = ejb.getCaSession();
    this.endEntitySession = ejb.getEndEntityManagementSession();
    this.certificateProfileSession = ejb.getCertificateProfileSession();
    this.endEntityProfileSession = ejb.getEndEntityProfileSession();
    this.keyValidatorSession = ejb.getKeyValidatorSession();
    this.publisherSession = ejb.getPublisherSession();
    this.administrator = authenticationToken;
    this.ejbcawebbean = anejbcawebbean;
  }

  /**
   * @param cainfo CA Info
   * @throws CAExistsException Fail
   * @throws CryptoTokenOfflineException Fail
   * @throws AuthorizationDeniedException Fail
   * @throws InvalidAlgorithmException Fail
   * @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */
  public void createCA(final CAInfo cainfo)
      throws CAExistsException, CryptoTokenOfflineException,
          AuthorizationDeniedException, InvalidAlgorithmException {
    caadminsession.createCA(administrator, cainfo);
  }

  /**
   * @param caname CA Name
   * @param p12file PKCS12 File
   * @param keystorepass Password
   * @param oprivateSignatureKeyAlias Alias
   * @param oprivateEncryptionKeyAlias Alias
   * @throws Exception Fail
   * @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */
  public void importCAFromKeyStore(
      final String caname,
      final byte[] p12file,
      final String keystorepass,
      final String oprivateSignatureKeyAlias,
      final String oprivateEncryptionKeyAlias)
      throws Exception {
    String privateSignatureKeyAlias = oprivateSignatureKeyAlias;
    String privateEncryptionKeyAlias = oprivateEncryptionKeyAlias;
    final KeyStore ks =
        KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
    ks.load(new ByteArrayInputStream(p12file), keystorepass.toCharArray());
    if (privateSignatureKeyAlias.equals("")) {
      Enumeration<String> aliases = ks.aliases();
      if (aliases == null || !aliases.hasMoreElements()) {
        throw new Exception("This file does not contain any aliases.");
      }
      privateSignatureKeyAlias = aliases.nextElement();
      if (aliases.hasMoreElements()) {
        while (aliases.hasMoreElements()) {
          privateSignatureKeyAlias += " " + aliases.nextElement();
        }
        throw new Exception(
            "You have to specify any of the following aliases: "
                + privateSignatureKeyAlias);
      }
    }
    if (privateEncryptionKeyAlias.equals("")) {
      privateEncryptionKeyAlias = null;
    }
    caadminsession.importCAFromKeyStore(
        administrator,
        caname,
        p12file,
        keystorepass,
        keystorepass,
        privateSignatureKeyAlias,
        privateEncryptionKeyAlias);
  }

  /**
   * @param caId CA ID
   * @param certbytes Bytes
   * @throws CertificateParsingException Fail
   * @throws CADoesntExistsException Fail
   * @throws AuthorizationDeniedException Fail
   * @throws CertificateImportException Fail
   * @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */
  public void importCACertUpdate(final int caId, final byte[] certbytes)
      throws CertificateParsingException, CADoesntExistsException,
          AuthorizationDeniedException, CertificateImportException {
    Collection<Certificate> certs = null;
    try {
      certs =
          CertTools.getCertsFromPEM(
              new ByteArrayInputStream(certbytes), Certificate.class);
    } catch (CertificateException e) {
      LOG.debug("Input stream is not PEM certificate(s): " + e.getMessage());
      // See if it is a single binary certificate
      certs = new ArrayList<>();
      certs.add(CertTools.getCertfromByteArray(certbytes, Certificate.class));
    }
    caadminsession.updateCACertificate(
        administrator, caId, EJBTools.wrapCertCollection(certs));
  }

  /**
   * @param caname CA NAme
   * @param certbytes Bytes
   * @throws Exception Exception
   * @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */
  public void importCACert(final String caname, final byte[] certbytes)
      throws Exception {
    Collection<Certificate> certs = null;
    try {
      certs =
          CertTools.getCertsFromPEM(
              new ByteArrayInputStream(certbytes), Certificate.class);
    } catch (CertificateException e) {
      LOG.debug("Input stream is not PEM certificate(s): " + e.getMessage());
      // See if it is a single binary certificate
      Certificate cert =
          CertTools.getCertfromByteArray(certbytes, Certificate.class);
      certs = new ArrayList<>();
      certs.add(cert);
    }
    caadminsession.importCACertificate(
        administrator, caname, EJBTools.wrapCertCollection(certs));
  }

  /**
   * @param cainfo CA Info
   * @throws AuthorizationDeniedException Fail
   * @throws CADoesntExistsException Fail
   * @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */
  public void editCA(final CAInfo cainfo)
      throws AuthorizationDeniedException, CADoesntExistsException {
    CAInfo oldinfo = caSession.getCAInfo(administrator, cainfo.getCAId());
    cainfo.setName(oldinfo.getName());
    if (cainfo.getStatus() != CAConstants.CA_UNINITIALIZED) {
      cainfo.setSubjectDN(oldinfo.getSubjectDN());
    }
    caadminsession.editCA(administrator, cainfo);
  }

  /**
   * Initializes a CA. The CA is updated with the values in caInfo, its status
   * is set to active and certificates are generated.
   *
   * @param caInfo CAInfo class containing updated information for the CA to
   *     initialize
   * @throws AuthorizationDeniedException if user was denied authorization to
   *     edit CAs
   * @throws CryptoTokenOfflineException if the keystore defined by the
   *     cryptotoken in caInfo has no keys
   * @throws CADoesntExistsException if the CA defined by caInfo doesn't exist.
   * @throws InvalidAlgorithmException Fail
   */
  public void initializeCA(final CAInfo caInfo)
      throws AuthorizationDeniedException, CADoesntExistsException,
          CryptoTokenOfflineException, InvalidAlgorithmException {
    CAInfo oldinfo = caSession.getCAInfo(administrator, caInfo.getCAId());
    caInfo.setName(oldinfo.getName());

    caadminsession.initializeCa(administrator, caInfo);
  }

  /**
   * @param caId CA ID
   * @return success
   * @throws AuthorizationDeniedException Fail
   * @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */
  public boolean removeCA(final int caId) throws AuthorizationDeniedException {
    final boolean caIdIsPresent =
        this.endEntitySession.checkForCAId(caId)
            || this.certificateProfileSession.existsCAIdInCertificateProfiles(
                caId)
            || this.endEntityProfileSession.existsCAInEndEntityProfiles(caId)
            || isCaIdInUseByRoleOrRoleMember(caId);
    if (!caIdIsPresent) {
      caSession.removeCA(administrator, caId);
    }
    return !caIdIsPresent;
  }

  /**
   * @param caId CA ID
   * @return true if the CA ID is in use by any Role's access rule or as
   *     RoleMember.tokenIssuerId
   */
  private boolean isCaIdInUseByRoleOrRoleMember(final int caId) {
    for (final Role role : roleDataSession.getAllRoles()) {
      if (role.getAccessRules()
          .containsKey(
              AccessRulesHelper.normalizeResource(
                  StandardRules.CAACCESS.resource() + caId))) {
        return true;
      }
      for (final RoleMember roleMember
          : roleMemberDataSession.findRoleMemberByRoleId(role.getRoleId())) {
        if (roleMember.getTokenIssuerId() == caId) {
          // Do more expensive checks if it is a potential match
          final AccessMatchValue accessMatchValue =
              AccessMatchValueReverseLookupRegistry.INSTANCE
                  .getMetaData(roleMember.getTokenType())
                  .getAccessMatchValueIdMap()
                  .get(roleMember.getTokenMatchKey());
          if (accessMatchValue.isIssuedByCa()) {
            return true;
          }
        }
      }
    }
    return false;
  }

  /**
   * @param caId CA ID
   * @param newname Name
   * @return true if CA with the new name already existed
   * @throws AuthorizationDeniedException Fail
   * @throws CADoesntExistsException Fail
   */
  public boolean renameCA(final int caId, final String newname)
      throws AuthorizationDeniedException, CADoesntExistsException {
    if (caId != 0 && newname != null && newname.length() > 0) {
      try {
        final String oldname = getCAIdToNameMap().get(Integer.valueOf(caId));
        caSession.renameCA(administrator, oldname, newname);
      } catch (CAExistsException e) {
        return true;
      }
    }
    return false;
  }

  /**
   * @param name Name
   * @return Info
   * @throws AuthorizationDeniedException Fail
   */
  public CAInfoView getCAInfo(final String name)
      throws AuthorizationDeniedException {
    CAInfoView cainfoview = null;
    CAInfo cainfo = caSession.getCAInfo(administrator, name);
    if (cainfo != null) {
      cainfoview =
          new CAInfoView(
              cainfo,
              ejbcawebbean,
              publisherSession.getPublisherIdToNameMap(),
              keyValidatorSession.getKeyValidatorIdToNameMap());
    }
    return cainfoview;
  }

  /**
   * @param name Name
   * @return Info
   */
  public CAInfoView getCAInfoNoAuth(final String name) {
    CAInfoView cainfoview = null;
    CAInfo cainfo = caSession.getCAInfoInternal(-1, name, true);
    if (cainfo != null) {
      cainfoview =
          new CAInfoView(
              cainfo,
              ejbcawebbean,
              publisherSession.getPublisherIdToNameMap(),
              keyValidatorSession.getKeyValidatorIdToNameMap());
    }
    return cainfoview;
  }

  /**
   * @param caid ID
   * @return Info
   */
  public CAInfoView getCAInfoNoAuth(final int caid) {
    final CAInfo cainfo = caSession.getCAInfoInternal(caid);
    return new CAInfoView(
        cainfo,
        ejbcawebbean,
        publisherSession.getPublisherIdToNameMap(),
        keyValidatorSession.getKeyValidatorIdToNameMap());
  }

  /**
   * @param caid ID
   * @return View
   * @throws AuthorizationDeniedException fail
   */
  public CAInfoView getCAInfo(final int caid)
      throws AuthorizationDeniedException {
    final CAInfo cainfo = caSession.getCAInfo(administrator, caid);
    return new CAInfoView(
        cainfo,
        ejbcawebbean,
        publisherSession.getPublisherIdToNameMap(),
        keyValidatorSession.getKeyValidatorIdToNameMap());
  }

  /**
   * @return Map
   * @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */
  public Map<Integer, String> getCAIdToNameMap() {
    return caSession.getCAIdToNameMap();
  }

  /**
   * @param caid CA ID
   * @param caChainBytes Chain
   * @param nextSignKeyAlias Alias
   * @return Reqiest
   * @throws CADoesntExistsException Fail
   * @throws AuthorizationDeniedException Fail
   * @throws CryptoTokenOfflineException Fail
   * @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */
  public byte[] makeRequest(
      final int caid, final byte[] caChainBytes, final String nextSignKeyAlias)
      throws CADoesntExistsException, AuthorizationDeniedException,
          CryptoTokenOfflineException {
    List<Certificate> certChain = null;
    if (caChainBytes != null) {
      try {
        certChain =
            CertTools.getCertsFromPEM(
                new ByteArrayInputStream(caChainBytes), Certificate.class);
        if (certChain.size() == 0) {
          throw new IllegalStateException(
              "Certificate chain contained no certificates");
        }
      } catch (Exception e) {
        // Maybe it's just a single binary CA cert
        try {
          Certificate cert =
              CertTools.getCertfromByteArray(caChainBytes, Certificate.class);
          certChain = new ArrayList<>();
          certChain.add(cert);
        } catch (CertificateParsingException e2) {
          // Ok.. so no chain was supplied.. we go ahead anyway..
          throw new CADoesntExistsException("Invalid CA chain file.");
        }
      }
    }
    try {
      return caadminsession.makeRequest(
          administrator, caid, certChain, nextSignKeyAlias);
    } catch (CertPathValidatorException e) {
      throw new RuntimeException("Unexpected outcome.", e);
    }
  }

  /**
   * @param caid CA ID
   * @param request Request
   * @return Sign request
   * @throws CADoesntExistsException Fail
   * @throws AuthorizationDeniedException Fail
   * @throws CryptoTokenOfflineException Fail
   * @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */
  public byte[] createAuthCertSignRequest(final int caid, final byte[] request)
      throws CADoesntExistsException, AuthorizationDeniedException,
          CryptoTokenOfflineException {
    return caadminsession.createAuthCertSignRequest(
        administrator, caid, request);
  }

  /**
   * @param caid CA ID
   * @param certBytes Certs
   * @param nextSignKeyAlias Alias
   * @param futureRollover bool
   * @throws Exception Fail
   * @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean#receiveResponse
   */
  public void receiveResponse(
      final int caid,
      final byte[] certBytes,
      final String nextSignKeyAlias,
      final boolean futureRollover)
      throws Exception {
    try {
      final List<Certificate> certChain = new ArrayList<>();
      try {
        certChain.addAll(
            CertTools.getCertsFromPEM(
                new ByteArrayInputStream(certBytes), Certificate.class));
      } catch (CertificateException e) {
        LOG.debug("Input stream is not PEM certificate(s): " + e.getMessage());
        // See if it is a single binary certificate
        certChain.add(
            CertTools.getCertfromByteArray(certBytes, Certificate.class));
      }
      if (certChain.size() == 0) {
        throw new Exception("No certificate(s) could be read.");
      }
      Certificate caCertificate = certChain.get(0);
      final X509ResponseMessage resmes = new X509ResponseMessage();
      resmes.setCertificate(caCertificate);
      caadminsession.receiveResponse(
          administrator,
          caid,
          resmes,
          certChain.subList(1, certChain.size()),
          nextSignKeyAlias,
          futureRollover);
    } catch (Exception e) {
      // log the error here, since otherwise it may be hidden by web pages...
      LOG.error("Error receiving response: ", e);
      throw e;
    }
  }

  /**
   * @param cainfo CA Info
   * @param requestmessage Request
   * @return Cert
   * @throws Exception Fail
   * @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */
  public Certificate processRequest(
      final CAInfo cainfo, final RequestMessage requestmessage)
      throws Exception {
    Certificate returnval = null;
    ResponseMessage result =
        caadminsession.processRequest(administrator, cainfo, requestmessage);
    if (result instanceof X509ResponseMessage) {
      returnval = ((X509ResponseMessage) result).getCertificate();
    }

    return returnval;
  }

  /**
   * @param caid ID
   * @param nextSignKeyAlias Alias
   * @param ocreateLinkCertificate Cert
   * @return Bool
   * @throws Exception Fail
   */
  public boolean renewCA(
      final int caid,
      final String nextSignKeyAlias,
      final boolean ocreateLinkCertificate)
      throws Exception {
    boolean createLinkCertificate = ocreateLinkCertificate;
    if (getCAInfo(caid).getCAInfo().getSignedBy()
        == CAInfo.SIGNEDBYEXTERNALCA) {
      return false;
    } else {
      if (getCAInfo(caid).getCAInfo().getCAType() == CAInfo.CATYPE_CVC) {
        // Force generation of link certificate for CVC CAs
        createLinkCertificate = true;
      }
      if (nextSignKeyAlias == null || nextSignKeyAlias.length() == 0) {
        // Generate new keys
        caadminsession.renewCA(
            administrator, caid, true, null, createLinkCertificate);
      } else {
        // Use existing keys
        caadminsession.renewCA(
            administrator, caid, nextSignKeyAlias, null, createLinkCertificate);
      }
      return true;
    }
  }

  /**
   * @param caid ID
   * @param nextSignKeyAlias Alias
   * @param createLinkCertificate Cert
   * @param newSubjectDn DN
   * @return Bool
   * @throws Exception Fail
   */
  public boolean renewAndRenameCA(
      final int caid,
      final String nextSignKeyAlias,
      final boolean createLinkCertificate,
      final String newSubjectDn)
      throws Exception {
    if (getCAInfo(caid).getCAInfo().getSignedBy()
        == CAInfo.SIGNEDBYEXTERNALCA) {
      return false;
    } else {
      if (nextSignKeyAlias == null || nextSignKeyAlias.length() == 0) {
        // Generate new keys
        caadminsession.renewCANewSubjectDn(
            administrator,
            caid,
            true,
            null,
            createLinkCertificate,
            newSubjectDn);
      } else {
        // Use existing keys
        caadminsession.renewCANewSubjectDn(
            administrator,
            caid,
            nextSignKeyAlias,
            null,
            createLinkCertificate,
            newSubjectDn);
      }
      return true;
    }
  }

  /**
   * @param caid CA ID
   * @param reason Reason
   * @throws CADoesntExistsException Fail
   * @throws AuthorizationDeniedException Fail
   * @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */
  public void revokeCA(final int caid, final int reason)
      throws CADoesntExistsException, AuthorizationDeniedException {
    caadminsession.revokeCA(administrator, caid, reason);
  }

  /**
   * @param caid CA ID
   * @throws AuthorizationDeniedException Fail
   * @throws CADoesntExistsException Fail
   */
  public void publishCA(final int caid)
      throws AuthorizationDeniedException, CADoesntExistsException {
    CAInfo cainfo = caSession.getCAInfo(administrator, caid);
    Collection<Integer> publishers = cainfo.getCRLPublishers();
    // Publish ExtendedCAServices certificates as well
    Iterator<ExtendedCAServiceInfo> iter =
        cainfo.getExtendedCAServiceInfos().iterator();
    while (iter.hasNext()) {
      ExtendedCAServiceInfo next = iter.next();
      // Only publish certificates for active services
      if (next.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) {
        // The OCSP certificate is the same as the CA signing certificate
        if (next instanceof BaseSigningCAServiceInfo) {
          List<Certificate> signingcert =
              ((BaseSigningCAServiceInfo) next).getCertificatePath();
          if (signingcert != null) {
            caadminsession.publishCACertificate(
                administrator, signingcert, publishers, cainfo.getSubjectDN());
          }
        }
      }
    }
    CertificateProfile certprofile =
        certificateProfileSession.getCertificateProfile(
            cainfo.getCertificateProfileId());
    // A CA certificate is published where the CRL is published and if there is
    // a publisher noted in the certificate profile
    // (which there is probably not)
    publishers.addAll(certprofile.getPublisherList());
    caadminsession.publishCACertificate(
        administrator,
        cainfo.getCertificateChain(),
        publishers,
        cainfo.getSubjectDN());
    caadminsession.publishCRL(
        administrator,
        cainfo.getCertificateChain().iterator().next(),
        publishers,
        cainfo.getSubjectDN(),
        cainfo.getDeltaCRLPeriod() > 0);
  }

  /**
   * Performs a rollover from the current certificate to the next certificate.
   *
   * @param caid C ID
   * @throws AuthorizationDeniedException FAil
   * @throws CryptoTokenOfflineException Fail
   * @see org.ejbca.core.ejb.ca.caadmin.CAAdminSession#rolloverCA
   */
  public void rolloverCA(final int caid)
      throws CryptoTokenOfflineException, AuthorizationDeniedException {
    caadminsession.rolloverCA(administrator, caid);
  }

  /**
   * @param caid ID
   * @throws CADoesntExistsException FAil
   * @throws CAOfflineException Fail
   * @throws CertificateRevokeException Fail
   * @throws AuthorizationDeniedException Fail
   */
  public void renewAndRevokeCmsCertificate(final int caid)
      throws CADoesntExistsException, CAOfflineException,
          CertificateRevokeException, AuthorizationDeniedException {
    caadminsession.renewAndRevokeCmsCertificate(administrator, caid);
  }

  /**
   * @param caid ID
   * @throws AuthorizationDeniedException fail
   * @throws ApprovalException fail
   * @throws WaitingForApprovalException fail
   * @throws CADoesntExistsException fail
   */
  public void activateCAToken(final int caid)
      throws AuthorizationDeniedException, ApprovalException,
          WaitingForApprovalException, CADoesntExistsException {
    caadminsession.activateCAService(administrator, caid);
  }

  /**
   * @param caid ID
   * @throws AuthorizationDeniedException fail
   * @throws CADoesntExistsException fail
   */
  public void deactivateCAToken(final int caid)
      throws AuthorizationDeniedException, CADoesntExistsException {
    caadminsession.deactivateCAService(administrator, caid);
  }

  /**
   * @param cainfo Info
   * @return Bool
   */
  public boolean isCARevoked(final CAInfo cainfo) {
    boolean retval = false;

    if (cainfo != null) {
      retval = RevokedCertInfo.isRevoked(cainfo.getRevocationReason());
    }
    return retval;
  }
}
