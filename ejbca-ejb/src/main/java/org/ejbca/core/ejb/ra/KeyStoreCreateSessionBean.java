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

package org.ejbca.core.ejb.ra;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import org.apache.log4j.Logger;
import org.cesecore.ErrorCode;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyStoreTools;
import org.cesecore.keys.util.KeyUtil;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBUtil;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.CertificateSignatureException;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.keyrecovery.KeyRecoveryInformation;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;

/**
 * Implementation of KeyStoreCreateSession Class that has helper methods to
 * generate tokens for users in ejbca.
 *
 * @version $Id: KeyStoreCreateSessionBean.java 29332 2018-06-25 13:39:58Z
 *     andresjakobs $
 */
@Stateless(
    mappedName = JndiConstants.APP_JNDI_PREFIX + "KeyStoreCreateSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class KeyStoreCreateSessionBean
    implements KeyStoreCreateSessionLocal, KeyStoreCreateSessionRemote {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(KeyStoreCreateSessionBean.class);

  /** Resource. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();

  /** EJB. */
  @EJB private GlobalConfigurationSessionLocal globalConfigurationSession;
  /** EJB. */
  @EJB private EndEntityAuthenticationSessionLocal authenticationSession;
  /** EJB. */
  @EJB private AuthorizationSessionLocal authorizationSession;
  /** EJB. */
  @EJB private EndEntityAccessSessionLocal endEntityAccessSession;

  /** EJB. */
  @EJB
  private EndEntityAuthenticationSessionLocal endEntityAuthenticationSession;

  /** EJB. */
  @EJB private EndEntityManagementSessionLocal endEntityManagementSession;
  /** EJB. */
  @EJB private EndEntityProfileSessionLocal endEntityProfileSession;
  /** EJB. */
  @EJB private CaSessionLocal caSession;
  /** EJB. */
  @EJB private KeyRecoverySessionLocal keyRecoverySession;
  /** EJB. */
  @EJB private SignSessionLocal signSession;
  /** EJB. */
  @EJB private HardTokenSessionLocal hardTokenSession;

  @Override
  public byte[] generateOrKeyRecoverTokenAsByteArray(
      final AuthenticationToken authenticationToken,
      final String username,
      final String password,
      final String hardTokenSN,
      final String keySpecification,
      final String keyAlgorithm)
      throws CADoesntExistsException, AuthorizationDeniedException,
          NotFoundException, EjbcaException {
    // Check if user exists.
    final EndEntityInformation endEntity =
        endEntityAccessSession.findUser(authenticationToken, username);
    if (endEntity == null) {
      LOG.info(INTRES.getLocalizedMessage("ra.errorentitynotexist", username));
      throw new NotFoundException(
          INTRES.getLocalizedMessage("ra.wrongusernameorpassword"));
    }
    // Check CA ID and authorization.
    final int caId = endEntity.getCAId();
    caSession.verifyExistenceOfCA(caId);
    if (!authorizationSession.isAuthorized(
        authenticationToken,
        StandardRules.CAACCESS.resource() + caId,
        StandardRules.CREATECERT.resource())) {
      final String msg =
          INTRES.getLocalizedMessage(
              "authorization.notauthorizedtoresource",
              StandardRules.CAACCESS.resource()
                  + caId
                  + ","
                  + StandardRules.CREATECERT.resource(),
              null);
      throw new AuthorizationDeniedException(msg);
    }
    // Check token type.
    if (endEntity.getTokenType() != SecConst.TOKEN_SOFT_P12) { // logger
      throw new EjbcaException(
          ErrorCode.BAD_USER_TOKEN_TYPE,
          "Error: Wrong Token Type of user, must be 'P12' for PKCS12 requests");
    }
    final boolean useKeyRecovery =
        ((GlobalConfiguration)
                globalConfigurationSession.getCachedConfiguration(
                    GlobalConfiguration.GLOBAL_CONFIGURATION_ID))
            .getEnableKeyRecovery();
    if (LOG.isDebugEnabled()) {
      LOG.debug("usekeyrecovery: " + useKeyRecovery);
    }
    final boolean saveKeys =
        endEntity.getKeyRecoverable()
            && useKeyRecovery
            && (endEntity.getStatus() != EndEntityConstants.STATUS_KEYRECOVERY);
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "userdata.getKeyRecoverable(): " + endEntity.getKeyRecoverable());
      LOG.debug("userdata.getStatus(): " + endEntity.getStatus());
      LOG.debug("savekeys: " + saveKeys);
    }
    final boolean loadKeys =
        (endEntity.getStatus() == EndEntityConstants.STATUS_KEYRECOVERY)
            && useKeyRecovery;
    if (LOG.isDebugEnabled()) {
      LOG.debug("loadkeys: " + loadKeys);
    }
    final int endEntityProfileId = endEntity.getEndEntityProfileId();
    final EndEntityProfile endEntityProfile =
        endEntityProfileSession.getEndEntityProfile(endEntityProfileId);
    final boolean reuseCertificate =
        endEntityProfile.getReUseKeyRecoveredCertificate();
    if (LOG.isDebugEnabled()) {
      LOG.debug("reusecertificate: " + reuseCertificate);
    }
    try {
      final KeyStore keyStore =
          generateOrKeyRecoverToken(
              authenticationToken,
              username,
              password,
              caId,
              keySpecification,
              keyAlgorithm,
              null,
              null,
              false,
              loadKeys,
              saveKeys,
              reuseCertificate,
              endEntityProfileId);
      final String alias = keyStore.aliases().nextElement();
      final X509Certificate certificate =
          (X509Certificate) keyStore.getCertificate(alias);
      if ((hardTokenSN != null) && (certificate != null)) {
        hardTokenSession.addHardTokenCertificateMapping(
            authenticationToken, hardTokenSN, certificate);
      }
      return KeyStoreTools.getAsByteArray(keyStore, password);
    } catch (
        AuthLoginException
            e) { // Is handled as EjbcaException at caller (EjbcaWS).
      throw e;
    } catch (
        AuthStatusException
            e) { // Is handled as EjbcaException at caller (EjbcaWS).
      throw e;
    } catch (Exception e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Re-throw exception in RA master API: " + e.getMessage(), e);
      }
      throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e.getMessage());
    }
  }

  @Override
  public byte[] generateOrKeyRecoverTokenAsByteArray(
      final AuthenticationToken administrator,
      final String username,
      final String password,
      final int caid,
      final String keyspec,
      final String keyalg,
      final boolean createJKS,
      final boolean loadkeys,
      final boolean savekeys,
      final boolean reusecertificate,
      final int endEntityProfileId)
      throws AuthorizationDeniedException, KeyStoreException,
          InvalidAlgorithmParameterException, CADoesntExistsException,
          IllegalKeyException, CertificateCreateException, IllegalNameException,
          CertificateRevokeException, CertificateSerialNumberException,
          CryptoTokenOfflineException, IllegalValidityException,
          CAOfflineException, InvalidAlgorithmException,
          CustomCertificateSerialNumberException, AuthStatusException,
          AuthLoginException, EndEntityProfileValidationException,
          NoSuchEndEntityException, CertificateSignatureException,
          CertificateEncodingException, CertificateException,
          NoSuchAlgorithmException, InvalidKeySpecException {
    KeyStore keyStore =
        generateOrKeyRecoverToken(
            administrator,
            username,
            password,
            caid,
            keyspec,
            keyalg,
            null,
            null,
            createJKS,
            loadkeys,
            savekeys,
            reusecertificate,
            endEntityProfileId);
    return KeyStoreTools.getAsByteArray(keyStore, password);
  }

  @Override
  public KeyStore generateOrKeyRecoverToken(
      final AuthenticationToken administrator,
      final String username,
      final String password,
      final int ocaid,
      final String okeyspec,
      final String okeyalg,
      final Date notBefore,
      final Date notAfter,
      final boolean createJKS,
      final boolean loadkeys,
      final boolean savekeys,
      final boolean reusecertificate,
      final int endEntityProfileId)
      throws AuthorizationDeniedException, KeyStoreException,
          InvalidAlgorithmParameterException, CADoesntExistsException,
          IllegalKeyException, CertificateCreateException, IllegalNameException,
          CertificateRevokeException, CertificateSerialNumberException,
          CryptoTokenOfflineException, IllegalValidityException,
          CAOfflineException, InvalidAlgorithmException,
          CustomCertificateSerialNumberException, AuthStatusException,
          AuthLoginException, EndEntityProfileValidationException,
          NoSuchEndEntityException, CertificateSignatureException,
          CertificateEncodingException, CertificateException,
          NoSuchAlgorithmException, InvalidKeySpecException {
    int caid = ocaid;
    String keyspec = okeyspec;
    String keyalg = okeyalg;
    if (LOG.isTraceEnabled()) {
      LOG.trace(">generateOrKeyRecoverToken");
    }
    boolean isNewToken = false;
    KeyRecoveryInformation keyData = null;
    KeyPair rsaKeys = null;
    EndEntityInformation userdata =
        endEntityAccessSession.findUser(administrator, username);
    if (userdata.getStatus() == EndEntityConstants.STATUS_NEW) {
      isNewToken = true;
    }
    if (loadkeys) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Recovering keys for user: " + username);
      }
      // used saved keys.
      keyData =
          keyRecoverySession.recoverKeys(
              administrator, username, endEntityProfileId);
      if (keyData == null) {
        throw new KeyStoreException("No key recovery data exists for user");
      }
      rsaKeys = keyData.getKeyPair();
      if (reusecertificate) {
        // This is only done if reusecertificate == true because if you don't
        // re-use certificate
        // signSession.createCertificate is called, which set status to
        // generated, unless finishUser == false in CA config
        if (LOG.isDebugEnabled()) {
          LOG.debug("Re-using old certificate for user: " + username);
        }
        keyRecoverySession.unmarkUser(administrator, username);
      }
      caid =
          keyData
              .getIssuerDN()
              .hashCode(); // always use the CA of the certificate
    } else {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Generating new keys for user: " + username);
      }

      // KeyStore algorithm specification inside endEntityInformation has
      // priority since its algorithm is approved
      if (userdata.getExtendedInformation() != null) {
        if (userdata.getExtendedInformation().getKeyStoreAlgorithmType() != null
            && userdata.getExtendedInformation().getKeyStoreAlgorithmSubType()
                != null) {
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Using the key-store algorithm specification found inside the"
                    + " endEntityInformation ("
                    + userdata
                        .getExtendedInformation()
                        .getKeyStoreAlgorithmType()
                    + "_"
                    + userdata
                        .getExtendedInformation()
                        .getKeyStoreAlgorithmSubType()
                    + ") instead of one provided separately ("
                    + keyalg
                    + "_"
                    + keyspec
                    + ")");
          }
          keyalg = userdata.getExtendedInformation().getKeyStoreAlgorithmType();
          keyspec =
              userdata.getExtendedInformation().getKeyStoreAlgorithmSubType();
        }
      }
      // generate new keys.
      rsaKeys = KeyUtil.genKeys(keyspec, keyalg);
    }
    X509Certificate cert = null;
    if ((reusecertificate) && (keyData != null)) {
      cert =
          (X509Certificate)
              keyData.getCertificate(); // TODO Validity ignored here?
      boolean finishUser = true;
      finishUser = caSession.getCAInfo(administrator, caid).getFinishUser();
      if (finishUser) {
        authenticationSession.finishUser(userdata);
      }
    } else {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Generating new certificate for user: " + username);
      }
      cert =
          (X509Certificate)
              signSession.createCertificate(
                  administrator,
                  username,
                  password,
                  new PublicKeyWrapper(rsaKeys.getPublic()),
                  -1,
                  notBefore,
                  notAfter);
    }
    // Clear password from database
    userdata =
        endEntityAccessSession.findUser(
            administrator, username); // Get GENERATED end entity information
    if (userdata.getStatus() == EndEntityConstants.STATUS_GENERATED) {
      // If we have a successful key recovery via EJBCA WS we implicitly want to
      // allow resetting of the password without edit_end_entity rights
      // (ECA-4947)
      if (loadkeys) {
        endEntityManagementSession.setClearTextPassword(
            new AlwaysAllowLocalAuthenticationToken(
                new UsernamePrincipal(
                    "Implicit authorization from key recovery operation to"
                        + " reset password.")),
            username,
            null);
      } else if (isNewToken) {
        // If we generate a new token through an enrollment, we don't want to
        // demand access to edit_end_entity
        endEntityManagementSession.setClearTextPassword(
            new AlwaysAllowLocalAuthenticationToken(
                new UsernamePrincipal(
                    "Implicit authorization from new enrollments")),
            username,
            null);
      } else {
        endEntityManagementSession.setClearTextPassword(
            administrator, username, null);
      }
    }
    // Make a certificate chain from the certificate and the CA-certificate
    Certificate[] cachain =
        signSession.getCertificateChain(caid).toArray(new Certificate[0]);
    // Verify CA-certificate
    Certificate rootcert = cachain[cachain.length - 1];
    if (CertTools.isSelfSigned(rootcert)) {
      try {
        rootcert.verify(rootcert.getPublicKey());
      } catch (GeneralSecurityException se) {
        throw new CertificateSignatureException(
            "RootCA certificate does not verify, issuerDN: "
                + CertTools.getIssuerDN(rootcert)
                + ", subjectDN: "
                + CertTools.getSubjectDN(rootcert),
            se);
      }
    } else {
      throw new CertificateSignatureException(
          "RootCA certificate not self-signed, issuerDN: "
              + CertTools.getIssuerDN(rootcert)
              + ", subjectDN: "
              + CertTools.getSubjectDN(rootcert));
    }
    // Verify that the user-certificate is signed by our CA
    Certificate cacert = cachain[0];
    try {
      cert.verify(cacert.getPublicKey());
    } catch (GeneralSecurityException se) {
      throw new CertificateSignatureException(
          "Generated certificate does not verify using CA-certificate,"
              + " issuerDN: "
              + CertTools.getIssuerDN(cert)
              + ", subjectDN: "
              + CertTools.getSubjectDN(cert)
              + ", caIssuerDN: "
              + CertTools.getIssuerDN(cacert)
              + ", caSubjectDN: "
              + CertTools.getSubjectDN(cacert),
          se);
    }
    if (savekeys) {
      // Save generated keys to database.
      if (LOG.isDebugEnabled()) {
        LOG.debug("Saving generated keys for recovery for user: " + username);
      }
      keyRecoverySession.addKeyRecoveryData(
          administrator, EJBUtil.wrap(cert), username, EJBUtil.wrap(rsaKeys));
    }
    //  Use CN if as alias in the keystore, if CN is not present use username
    String alias = CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN");
    if (alias == null) {
      alias = username;
    }
    // Store keys and certificates in keystore.
    KeyStore ks = null;
    if (createJKS) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Generating JKS for user: " + username);
      }
      ks =
          KeyUtil.createJKS(
              alias, rsaKeys.getPrivate(), password, cert, cachain);
    } else {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Generating PKCS12 for user: " + username);
      }
      ks = KeyUtil.createP12(alias, rsaKeys.getPrivate(), cert, cachain);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<generateOrKeyRecoverToken");
    }
    return ks;
  }
}
