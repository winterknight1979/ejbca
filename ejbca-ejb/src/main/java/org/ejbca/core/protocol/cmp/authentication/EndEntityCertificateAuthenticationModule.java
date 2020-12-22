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

package org.ejbca.core.protocol.cmp.authentication;

import java.lang.reflect.InvocationTargetException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSession;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.CertTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.protocol.cmp.CmpMessageHelper;
import org.ejbca.core.protocol.cmp.CmpPKIBodyConstants;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

/**
 * Check the authentication of the PKIMessage by verifying the signature of the
 * administrator who sent the message.
 *
 * @version $Id: EndEntityCertificateAuthenticationModule.java 30979 2019-01-03
 *     16:25:25Z samuellb $
 */
public class EndEntityCertificateAuthenticationModule
    implements ICMPAuthenticationModule {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(EndEntityCertificateAuthenticationModule.class);

  /** Param. */
  private final String authenticationparameter;
  /** Param. */
  private String password;
  /** Param. */
  private String errorMessage;
  /** Param. */
  private Certificate extraCert;
  /** Param. */
  private final String confAlias;
  /** Param. */
  private final CmpConfiguration cmpConfiguration;
  /** Param. */
  private final boolean authenticated;

  /** Param. */
  private final AuthenticationToken admin;
  /** Param. */
  private final CaSession caSession;
  /** Param. */
  private final CertificateStoreSession certSession;
  /** Param. */
  private final AuthorizationSession authSession;
  /** Param. */
  private final EndEntityProfileSession eeProfileSession;
  /** Param. */
  private final CertificateProfileSession certProfileSession;
  /** Param. */
  private final EndEntityAccessSession eeAccessSession;
  /** Param. */
  private final WebAuthenticationProviderSessionLocal
      authenticationProviderSession;
  /** Param. */
  private final EndEntityManagementSession eeManagementSession;

  /** Definition of the optional Vendor mode implementation. */
  private static final String IMPL_CLASS_NAME =
      "org.ejbca.core.protocol.cmp.authentication.CmpVendorModeImpl";
  /**
   * Cache class so we don't have to do Class.forName for every entity object
   * created.
   */
  private static volatile Class<?> implClass = null;
  /**
   * Optimization variable so we don't have to check for existence of implClass
   * for every construction of an object.
   */
  private static volatile boolean implExists = true;
  /** Param. */
  private CmpVendorMode impl;

  /**
   * @param anadmin Admin
   * @param authparam Auth
   * @param aconfAlias Config
   * @param acmpConfig CMP config
   * @param isauthenticated bool
   * @param acaSession CA
   * @param acertSession Cert
   * @param anauthSession Auth
   * @param eeprofSession Profile
   * @param cprofSession Profile
   * @param eeaccessSession Access
   * @param authProvSession Provider
   * @param endEntityManagementSession Management
   */
  public EndEntityCertificateAuthenticationModule(
      final AuthenticationToken anadmin,
      final String authparam,
      final String aconfAlias,
      final CmpConfiguration acmpConfig,
      final boolean isauthenticated,
      final CaSession acaSession,
      final CertificateStoreSession acertSession,
      final AuthorizationSession anauthSession,
      final EndEntityProfileSession eeprofSession,
      final CertificateProfileSession cprofSession,
      final EndEntityAccessSession eeaccessSession,
      final WebAuthenticationProviderSessionLocal authProvSession,
      final EndEntityManagementSession endEntityManagementSession) {
    authenticationparameter = authparam;
    password = null;
    errorMessage = null;
    extraCert = null;
    this.confAlias = aconfAlias;
    this.cmpConfiguration = acmpConfig;
    this.authenticated = isauthenticated;

    this.admin = anadmin;
    this.caSession = acaSession;
    this.certSession = acertSession;
    this.authSession = anauthSession;
    this.eeProfileSession = eeprofSession;
    this.certProfileSession = cprofSession;
    eeAccessSession = eeaccessSession;
    authenticationProviderSession = authProvSession;
    eeManagementSession = endEntityManagementSession;

    createVendorModeImpl();
  }

  /**
   * Creates the implementation for CMP vendor mode, if it exists. If it does
   * not exist, uses a CmpVendorModeNoop implementation that return false on the
   * question of CMP Vendor mode is used.
   */
  private void createVendorModeImpl() {
    if (implExists) {
      try {
        if (implClass == null) {
          // We only end up here once, if the class does not exist, we will
          // never end up here again (ClassNotFoundException)
          // and if the class exists we will never end up here again (it will
          // not be null)
          implClass = Class.forName(IMPL_CLASS_NAME);
          LOG.debug(
              "CmpVendorModeImpl is available, and used, in this version of"
                  + " EJBCA.");
        }
        impl = (CmpVendorMode) implClass.getConstructor().newInstance();
        impl.setCaSession(caSession);
        impl.setCmpConfiguration(cmpConfiguration);
      } catch (ClassNotFoundException | NoSuchMethodException e) {
        // We only end up here once, if the class does not exist, we will never
        // end up here again
        implExists = false;
        LOG.info("CMP Vendor mode is not available in the version of EJBCA.");
        impl = new CmpVendorModeNoopImpl();
      } catch (InstantiationException | InvocationTargetException e) {
        LOG.error("Error intitilizing CmpVendorMode: ", e);
      } catch (IllegalAccessException e) {
        LOG.error("Error intitilizing CmpVendorMode: ", e);
      }
    } else {
      impl = new CmpVendorModeNoopImpl();
    }
  }

  @Override
  public String getName() {
    return CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE;
  }

  @Override
  public String getAuthenticationString() {
    return this.password;
  }

  @Override
  public String getErrorMessage() {
    return this.errorMessage;
  }

  /**
   * Get the certificate that was attached to the CMP request in it's extraCert
   * filed.
   *
   * @return The certificate that was attached to the CMP request in it's
   *     extraCert filed
   */
  public Certificate getExtraCert() {
    return extraCert;
  }

  /**
   * Get the end entity certificate that was attached to the CMP request in it's
   * extreCert filed. If the extraCerts field contains multiple certificates,
   * these are ordered in a CertPath and the leaf certificate is returned.
   *
   * @param msg Message
   * @return The end entity certificate that was attached to the CMP request in
   *     it's extraCert field, or null, as an ordered certificate path with leaf
   *     certificate in first position
   */
  private List<X509Certificate> getExtraCerts(final PKIMessage msg) {
    final CMPCertificate[] extraCerts = msg.getExtraCerts();
    if ((extraCerts == null) || (extraCerts.length == 0)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "There are no certificates in the extraCert field in the"
                + " PKIMessage");
      }
      return null;
    } else {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            extraCerts.length
                + " certificate(s) found in the extraCert field in the CMP"
                + " message");
      }
    }

    try {
      // Read the extraCerts. Convert to an array of normal X509Certificates so
      // we can later use a regular CertPath validator
      List<X509Certificate> certlist = new ArrayList<X509Certificate>();
      // Create CertPath
      final JcaX509CertificateConverter jcaX509CertificateConverter =
          new JcaX509CertificateConverter();
      for (int i = 0; i < extraCerts.length; i++) {
        certlist.add(
            jcaX509CertificateConverter.getCertificate(
                new X509CertificateHolder(extraCerts[i].getX509v3PKCert())));
      }
      if (!certlist.isEmpty()) {
        List<X509Certificate> orderedCerts =
            CertTools.orderX509CertificateChain(certlist);
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Obtaining "
                  + certlist.size()
                  + " certificate(s) from extraCert field was done"
                  + " successfully.");
        }
        if (LOG.isTraceEnabled()) {
          LOG.trace("extraCerts obtained: " + orderedCerts);
        }
        return orderedCerts;
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Obtaining the certificate from extraCert field failed, the"
                  + " result was null.");
        }
      }
    } catch (CertificateException e) {
      // We only log debug to prevent DOS attacks (log spamming) by sending
      // invalid messages
      if (LOG.isDebugEnabled()) {
        LOG.debug(e.getLocalizedMessage(), e);
      }
    } catch (CertPathValidatorException e) {
      // We only log debug to prevent DOS attacks (log spamming) by sending
      // invalid messages
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "extraCerts does not contain a valid certificate path: "
                + e.getMessage());
      }
    }
    return null;
  }

  @Override
  /*
   * Verifies the signature of 'msg'. msg should be signed and the signer's
   * certificate should be
   * attached in msg in the extraCert field.
   *
   * When successful, the authentication string is set.
   */
  public boolean verifyOrExtract(final PKIMessage msg, final String username) {

    // Check that msg is signed
    if (msg.getProtection() == null) {
      this.errorMessage =
          "PKI Message is not authenticated properly. No PKI protection is"
              + " found.";
      return false;
    }

    // Read the extraCert and store it in a local variable
    List<X509Certificate> extraCertPath = getExtraCerts(msg);
    extraCert = (extraCertPath != null ? extraCertPath.get(0) : null);
    if (extraCert == null) {
      this.errorMessage =
          "Error while reading the certificate in the extraCert field";
      return false;
    }

    // A CMP KeyUpdateRequest is always regarding an end entity that already
    // exists. If that end entity
    // does not exist, no point in looking further
    EndEntityInformation endentity = null;
    if (msg.getBody().getType() == CmpPKIBodyConstants.KEYUPDATEREQUEST) {
      try {
        endentity = getEndEntityFromKeyUpdateRequest(msg);
      } catch (AuthorizationDeniedException e1) {
        // note: this should not happen since at this point, this is an
        // AlwaysAllowed token
        this.errorMessage =
            "Administrator "
                + admin.toString()
                + " is not authorized to retrieve end entity";
        return false;
      }
      if (endentity == null) {
        this.errorMessage =
            "Error. Received a CMP KeyUpdateRequest for a non-existing end"
                + " entity";
        return false;
      }
    }

    boolean vendormode =
        impl.isVendorCertificateMode(msg.getBody().getType(), this.confAlias);
    boolean omitVerifications =
        cmpConfiguration.getOmitVerificationsInEEC(confAlias);
    boolean ramode = cmpConfiguration.getRAMode(confAlias);
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "CMP is operating in RA mode: "
              + this.cmpConfiguration.getRAMode(this.confAlias));
      LOG.debug("CMP is operating in Vendor mode: " + vendormode);
      LOG.debug("CMP message already been authenticated: " + authenticated);
      LOG.debug("Omitting some verifications: " + omitVerifications);
      LOG.debug(
          "CMP message (claimed to be) signed by (cert from extraCerts):"
              + " SubjectDN '"
              + CertTools.getSubjectDN(extraCert)
              + "' IssuerDN '"
              + CertTools.getIssuerDN(extraCert)
              + "'");
    }

    // ---------------------------------------------------------------------
    // Perform the different checks depending on the configuration and previous
    // authentication
    // ---------------------------------------------------------------------

    // Not allowed combinations.
    if (ramode && vendormode) {
      this.errorMessage = "Vendor mode and RA mode cannot be combined";
      return false;
    }
    if (omitVerifications && (!ramode || !authenticated)) {
      this.errorMessage =
          "Omitting some verifications can only be accepted in RA mode and"
              + " when the CMP request has already been authenticated, for"
              + " example, through the use of NestedMessageContent";
      return false;
    }

    // Accepted combinations
    if (omitVerifications && ramode && authenticated) {
      // Do nothing here
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Skipping some verification of the extraCert certificate in RA"
                + " mode and an already authenticated CMP message, tex."
                + " through NestedMessageContent");
      }
    } else if (ramode) {

      // Get the CA to use for the authentication
      CAInfo cainfo = getCAInfoByName(authenticationparameter);
      if (cainfo == null) {
        return false;
      }

      // Check that extraCert is in the Database
      CertificateInfo certinfo =
          certSession.getCertificateInfo(
              CertTools.getFingerprintAsString(extraCert));
      if (certinfo == null) {
        this.errorMessage =
            "The certificate attached to the PKIMessage in the extraCert field"
                + " could not be found in the database.";
        return false;
      }

      // More extraCert verifications
      if (!isExtraCertValidAndIssuedByCA(extraCertPath, cainfo)
          || !isExtraCertActive(certinfo)) {
        return false;
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Certificate in extraCerts field is issued by "
                  + cainfo.getName()
                  + ", is valid and active");
        }
      }

      // Check that extraCert belong to an admin with sufficient access rights
      if (!isAuthorizedAdmin(certinfo, msg, endentity)) {
        this.errorMessage =
            "'"
                + CertTools.getSubjectDN(extraCert)
                + "' is not an authorized administrator.";
        return false;
      }

    } else if (!ramode) { // client mode

      String extraCertUsername = null;
      if (vendormode) {

        // Check that extraCert is issued  by a configured VendorCA
        final CAInfo cainfo =
            impl.isExtraCertIssuedByVendorCA(
                admin, this.confAlias, extraCertPath);
        if (cainfo == null) {
          this.errorMessage =
              "The certificate in extraCert field is not issued by any of the"
                  + " configured Vendor CAs: "
                  + cmpConfiguration.getVendorCA(confAlias);
          return false;
        }

        // Extract the username from extraCert to use for  further
        // authentication
        String subjectDN = CertTools.getSubjectDN(extraCert);
        extraCertUsername =
            CertTools.getPartFromDN(
                subjectDN,
                this.cmpConfiguration.getExtractUsernameComponent(
                    this.confAlias));
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Username ("
                  + extraCertUsername
                  + ") was extracted from the '"
                  + this.cmpConfiguration.getExtractUsernameComponent(
                      this.confAlias)
                  + "' part of the subjectDN of the certificate in the"
                  + " 'extraCerts' field.");
        }

        // More extraCert verifications
        if (!isExtraCertValidAndIssuedByCA(extraCertPath, cainfo)) {
          return false;
        }
      } else {

        // Get the CA to use for the authentication
        CAInfo cainfo = getCAInfoByIssuer(CertTools.getIssuerDN(extraCert));
        // Check that extraCert is in the Database
        CertificateInfo certinfo =
            certSession.getCertificateInfo(
                CertTools.getFingerprintAsString(extraCert));
        if (certinfo == null) {
          this.errorMessage =
              "The certificate attached to the PKIMessage in the extraCert"
                  + " field could not be found in the database.";
          return false;
        }

        // More extraCert verifications
        if (!isExtraCertValidAndIssuedByCA(extraCertPath, cainfo)
            || !isExtraCertActive(certinfo)) {
          return false;
        }

        // Extract the username from extraCert to use for  further
        // authentication
        extraCertUsername = certinfo.getUsername();
      }

      // Check if this certificate belongs to the user
      if ((username != null) && (extraCertUsername != null)) {
        if (cmpConfiguration.getVendorMode(this.confAlias)) {
          String fix = cmpConfiguration.getRANameGenPrefix(this.confAlias);
          if (StringUtils.isNotBlank(fix)) {
            LOG.info(
                "Preceded RA name prefix '"
                    + fix
                    + "' to username '"
                    + username
                    + "' in CMP vendor mode.");
            extraCertUsername = fix + extraCertUsername;
          }
          fix = cmpConfiguration.getRANameGenPostfix(this.confAlias);
          if (StringUtils.isNotBlank(
              cmpConfiguration.getRANameGenPostfix(this.confAlias))) {
            LOG.info(
                "Attached RA name postfix '"
                    + fix
                    + "' to username '"
                    + username
                    + "' in CMP vendor mode.");
            extraCertUsername += fix;
          }
        }
        if (!StringUtils.equals(username, extraCertUsername)) {
          this.errorMessage =
              "The End Entity certificate attached to the PKIMessage in the"
                  + " extraCert field does not belong to user '"
                  + username
                  + "'";
          if (LOG.isDebugEnabled()) {
            // Use a different debug message, as not to reveal too much
            // information
            LOG.debug(
                this.errorMessage
                    + ", but to user '"
                    + extraCertUsername
                    + "'");
          }
          return false;
        }

        // set the password of the request to this user's password so it can
        // later be used when issuing the certificate
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "The End Entity certificate attached to the PKIMessage in the"
                  + " extraCert field belongs to user '"
                  + username
                  + "'.");
          LOG.debug(
              "Extracting and setting password for user '" + username + "'.");
        }
        try {
          EndEntityInformation user = eeAccessSession.findUser(admin, username);
          password = user.getPassword();
          if (password == null) {
            password = genRandomPwd();
            user.setPassword(password);
            eeManagementSession.changeUser(admin, user, false);
          }
        } catch (AuthorizationDeniedException
            | IllegalNameException
            | CADoesntExistsException
            | EndEntityProfileValidationException
            | WaitingForApprovalException
            | CertificateSerialNumberException
            | ApprovalException
            | NoSuchEndEntityException
            | CustomFieldException e) {
          if (LOG.isDebugEnabled()) {
            LOG.debug(e.getLocalizedMessage());
          }
          this.errorMessage = e.getLocalizedMessage();
          return false;
        }
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Certificate does not belong to user. Username='"
                  + username
                  + "', extraCert username='"
                  + extraCertUsername
                  + "'.");
        }
      }
    }

    // -------------------------------------------------------------
    // Begin the signature verification process.
    // Verify the signature of msg using the public key of extraCert
    // -------------------------------------------------------------
    try {
      final Signature sig =
          Signature.getInstance(
              msg.getHeader().getProtectionAlg().getAlgorithm().getId(),
              BouncyCastleProvider.PROVIDER_NAME);
      sig.initVerify(extraCert.getPublicKey());
      sig.update(CmpMessageHelper.getProtectedBytes(msg));
      if (sig.verify(msg.getProtection().getBytes())) {
        if (password == null) {
          // If not set earlier
          password = genRandomPwd();
        }
      } else {
        this.errorMessage = "Failed to verify the signature in the PKIMessage";
        return false;
      }
    } catch (InvalidKeyException e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(e.getLocalizedMessage());
      }
      this.errorMessage = e.getLocalizedMessage();
      return false;
    } catch (NoSuchAlgorithmException e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(e.getLocalizedMessage());
      }
      this.errorMessage = e.getLocalizedMessage();
      return false;
    } catch (NoSuchProviderException e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(e.getLocalizedMessage());
      }
      this.errorMessage = e.getLocalizedMessage();
      return false;
    } catch (SignatureException e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(e.getLocalizedMessage());
      }
      this.errorMessage = e.getLocalizedMessage();
      return false;
    }

    return this.password != null;
  }

  /**
   * Generated a random password of 16 digits.
   *
   * @return a randomly generated password
   */
  private String genRandomPwd() {
    final int len = 12;
    final IPasswordGenerator pwdgen =
        PasswordGeneratorFactory.getInstance(
            PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE);
    return pwdgen.getNewPassword(len, len);
  }

  private EndEntityInformation getEndEntityFromKeyUpdateRequest(
      final PKIMessage pkimessage) throws AuthorizationDeniedException {
    String subjectDN = "";
    String issuerDN = "";

    if (cmpConfiguration.getRAMode(confAlias)) {
      CertReqMessages kur = (CertReqMessages) pkimessage.getBody().getContent();
      CertReqMsg certmsg;
      try {
        certmsg = kur.toCertReqMsgArray()[0];
      } catch (Exception e) {
        LOG.debug(
            "Could not parse the KeyUpdate request. Trying to parse it as"
                + " novosec generated message.");
        certmsg = CmpMessageHelper.getNovosecCertReqMsg(kur);
        if (certmsg == null) {
          LOG.info(
              "Error. Failed to parse CMP message novosec generated message. "
                  + e.getLocalizedMessage());
          if (LOG.isDebugEnabled()) {
            LOG.debug(e);
          }
          return null;
        } else {
          if (LOG.isDebugEnabled()) {
            LOG.debug("Succeeded in parsing the novosec generated request.");
          }
        }
      }

      X500Name dn = certmsg.getCertReq().getCertTemplate().getSubject();
      if (dn != null) {
        subjectDN = dn.toString();
      }
      dn = certmsg.getCertReq().getCertTemplate().getIssuer();
      if (dn != null) {
        issuerDN = dn.toString();
      }
    } else {
      subjectDN = CertTools.getSubjectDN(extraCert);
      issuerDN = CertTools.getIssuerDN(extraCert);
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Received a CMP KeyUpdateRequest for an endentity with SubjectDN '"
              + subjectDN
              + "' and issuerDN '"
              + issuerDN
              + "'");
    }

    EndEntityInformation userdata = null;
    if (StringUtils.isEmpty(issuerDN)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("The CMP KeyUpdateRequest did not specify an issuer");
      }
      List<EndEntityInformation> userdataList =
          eeAccessSession.findUserBySubjectDN(admin, subjectDN);
      if (userdataList.size() > 0) {
        userdata = userdataList.get(0);
      }
      if (userdataList.size() > 1) {
        LOG.warn(
            "Multiple end entities with subject DN "
                + subjectDN
                + " were found. This may lead to unexpected behavior.");
      }
    } else {
      List<EndEntityInformation> userdataList =
          eeAccessSession.findUserBySubjectAndIssuerDN(
              admin, subjectDN, issuerDN);
      if (userdataList.size() > 0) {
        userdata = userdataList.get(0);
      }
      if (userdataList.size() > 1) {
        LOG.warn(
            "Multiple end entities with subject DN "
                + subjectDN
                + " and issuer DN"
                + issuerDN
                + " were found. This may lead to unexpected behavior.");
      }
    }

    return userdata;
  }

  /**
   * Checks if cert belongs to an administrator who is authorized to process the
   * request.
   *
   * @param certInfo Info
   * @param msg Message
   * @param endentity Only used when the message received is a KeyUpdateRequest
   *     in RA mode. The administrator is authorized to handle a
   *     KeyUpdateRequest in RA mode if it is authorized to the
   *     EndEntityProfile, CertificateProfile and the CA specified in this end
   *     entity.
   * @return true if the administrator is authorized to process the request and
   *     false otherwise.
   */
  private boolean isAuthorizedAdmin(
      final CertificateInfo certInfo,
      final PKIMessage msg,
      final EndEntityInformation endentity) {

    X509Certificate x509cert = (X509Certificate) extraCert;
    Set<X509Certificate> credentials = new HashSet<X509Certificate>();
    credentials.add(x509cert);

    AuthenticationSubject subject =
        new AuthenticationSubject(null, credentials);
    AuthenticationToken reqAuthToken =
        authenticationProviderSession.authenticate(subject);

    final int tagnr = msg.getBody().getType();
    if ((tagnr == CmpPKIBodyConstants.CERTIFICATAIONREQUEST)
        || (tagnr == CmpPKIBodyConstants.INITIALIZATIONREQUEST)) {

      final int eeprofid;
      final String eepname;
      try {
        final String configuredId =
            this.cmpConfiguration.getRAEEProfile(this.confAlias);
        if (StringUtils.equals(
            CmpConfiguration.PROFILE_USE_KEYID, configuredId)) {
          eepname =
              CmpMessageHelper.getStringFromOctets(
                  msg.getHeader().getSenderKID());
          eeprofid = eeProfileSession.getEndEntityProfileId(eepname);
        } else {
          eeprofid = Integer.parseInt(configuredId);
          eepname = eeProfileSession.getEndEntityProfileName(eeprofid);
        }
        if (eepname == null) {
          LOG.error(
              "End Entity Profile with ID " + configuredId + " was not found");
          return false;
        }
      } catch (NumberFormatException e) {
        LOG.error(
            "End Entity Profile ID "
                + this.cmpConfiguration.getRAEEProfile(this.confAlias)
                + " in CMP alias "
                + this.confAlias
                + " was not an integer");
        return false;
      } catch (EndEntityProfileNotFoundException e) {
        LOG.error(
            "End Entity Profile Name specified in the senderKID field could"
                + " not be mapped to an end entity profile ID: "
                + e.getMessage());
        return false;
      }

      if (!authorizedToEndEntityProfile(
          reqAuthToken, eeprofid, AccessRulesConstants.CREATE_END_ENTITY)) {
        LOG.info(
            "Administrator "
                + reqAuthToken.toString()
                + " was not authorized to create end entities with"
                + " EndEntityProfile "
                + eepname);
        return false;
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Administrator "
                  + reqAuthToken.toString()
                  + " was authorized to create end entities with"
                  + " EndEntityProfile "
                  + eepname);
        }
      }

      if (!authorizedToEndEntityProfile(
          reqAuthToken, eeprofid, AccessRulesConstants.EDIT_END_ENTITY)) {
        LOG.info(
            "Administrator "
                + reqAuthToken.toString()
                + " was not authorized to edit end entities with"
                + " EndEntityProfile "
                + eepname);
        return false;
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Administrator "
                  + reqAuthToken.toString()
                  + " was authorized to edit end entities with"
                  + " EndEntityProfile "
                  + eepname);
        }
      }

      if (!authSession.isAuthorizedNoLogging(
          reqAuthToken, AccessRulesConstants.REGULAR_CREATECERTIFICATE)) {
        LOG.info(
            "Administrator "
                + reqAuthToken.toString()
                + " is not authorized to create certificates.");
        return false;
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Administrator "
                  + reqAuthToken.toString()
                  + " was authorized to create certificates");
        }
      }

      final EndEntityProfile eep =
          eeProfileSession.getEndEntityProfile(eeprofid);
      final int caid =
          getRaCaId((DEROctetString) msg.getHeader().getSenderKID(), eep);
      if (!authSession.isAuthorizedNoLogging(
          reqAuthToken, StandardRules.CAACCESS.resource() + caid)) {
        LOG.info(
            "Administrator "
                + reqAuthToken.toString()
                + " not authorized to resource "
                + StandardRules.CAACCESS.resource()
                + caid);
        return false;
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Administrator "
                  + reqAuthToken.toString()
                  + " is authorized to access CA with ID "
                  + caid);
        }
      }

      CertificateProfile cp =
          getCertificateProfileFromCrmf(
              eep, (DEROctetString) msg.getHeader().getSenderKID());
      if (!isCertificateProfileAuthorizedToCA(cp, caid)) {
        LOG.info("CertificateProfile is not authorized to CA with ID: " + caid);
        return false;
      }

    } else if (tagnr == CmpPKIBodyConstants.KEYUPDATEREQUEST) {
      // Because we do not edit the end entity when we receive a
      // KeyUpdateRequest (the only editing we do is reset the end entity
      // status),
      // the CertificateProfile and CA that will be used to issue the new
      // certificate will be the ones already set in the end entity
      // regardless of the content of the request or the configuration of the
      // CMP alias.
      // It is, however, possible to edit the profiles and CA in the end entity
      // (we just do not do that when receiving a CMPKeyUpdateRequest),
      // So if we change the implementation in CrmfKeyUpdateHandler.java, this
      // check should be updated accordingly

      final int eeprofid = endentity.getEndEntityProfileId();
      final String eepname = eeProfileSession.getEndEntityProfileName(eeprofid);
      if (eepname == null) {
        LOG.error("End Entity Profile with ID " + eeprofid + " was not found");
        return false;
      }

      if (!authorizedToEndEntityProfile(
          reqAuthToken, eeprofid, AccessRulesConstants.EDIT_END_ENTITY)) {
        LOG.info(
            "Administrator "
                + reqAuthToken.toString()
                + " was not authorized to edit end entities with"
                + " EndEntityProfile "
                + eepname);
        return false;
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Administrator "
                  + reqAuthToken.toString()
                  + " was authorized to edit end entities with"
                  + " EndEntityProfile "
                  + eepname);
        }
      }

      if (!authSession.isAuthorizedNoLogging(
          reqAuthToken, AccessRulesConstants.REGULAR_CREATECERTIFICATE)) {
        LOG.info(
            "Administrator "
                + reqAuthToken.toString()
                + " is not authorized to create certificates.");
        return false;
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Administrator "
                  + reqAuthToken.toString()
                  + " is authorized to create certificates");
        }
      }

      final int caid = endentity.getCAId();
      if (!authSession.isAuthorizedNoLogging(
          reqAuthToken, StandardRules.CAACCESS.resource() + caid)) {
        LOG.info(
            "Administrator "
                + reqAuthToken.toString()
                + " not authorized to resource "
                + StandardRules.CAACCESS.resource()
                + caid);
        return false;
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Administrator "
                  + reqAuthToken.toString()
                  + " is authorized to access CA with ID "
                  + caid);
        }
      }

      if (!isCertificateProfileAuthorizedToCA(
          certProfileSession.getCertificateProfile(
              endentity.getCertificateProfileId()),
          caid)) {
        LOG.info(
            "CertificateProfile "
                + certProfileSession.getCertificateProfileName(
                    endentity.getCertificateProfileId())
                + " is not authorized to CA with ID: "
                + caid);
        return false;
      }

    } else if (tagnr == CmpPKIBodyConstants.REVOCATIONREQUEST) {
      final String issuerdn =
          getIssuerDNFromRevRequest((RevReqContent) msg.getBody().getContent());
      final int caid = CertTools.stringToBCDNString(issuerdn).hashCode();
      if (!authSession.isAuthorizedNoLogging(
          reqAuthToken, StandardRules.CAACCESS.resource() + caid)) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Administrator "
                  + reqAuthToken.toString()
                  + " NOT authorized to revoke certificates issues by "
                  + issuerdn);
        }
        return false;
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Administrator "
                  + reqAuthToken.toString()
                  + " is authorized to revoke certificates issued by "
                  + issuerdn);
        }
      }

      if (!authSession.isAuthorizedNoLogging(
          reqAuthToken, AccessRulesConstants.REGULAR_REVOKEENDENTITY)) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Administrator "
                  + reqAuthToken.toString()
                  + " is not authorized to revoke End Entities");
        }
        return false;
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Administrator "
                  + reqAuthToken.toString()
                  + " was authorized to revoke end entities");
        }
      }
    }
    return true;
  }

  /**
   * Checks whether admin is authorized to access the EndEntityProfile with the
   * ID profileid.
   *
   * @param anadmin Admin
   * @param profileid ID
   * @param rights Rights
   * @return true if admin is authorized and false otherwise.
   */
  private boolean authorizedToEndEntityProfile(
      final AuthenticationToken anadmin,
      final int profileid,
      final String rights) {
    if (profileid == EndEntityConstants.EMPTY_END_ENTITY_PROFILE
        && (rights.equals(AccessRulesConstants.CREATE_END_ENTITY)
            || rights.equals(AccessRulesConstants.EDIT_END_ENTITY))) {

      return authSession.isAuthorizedNoLogging(
          anadmin, StandardRules.ROLE_ROOT.resource());
    } else {
      return authSession.isAuthorizedNoLogging(
              anadmin,
              AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + rights)
          && authSession.isAuthorizedNoLogging(
              anadmin, AccessRulesConstants.REGULAR_RAFUNCTIONALITY + rights);
    }
  }

  /**
   * Returns the IssuerDN specified in the CMP revocation request.
   *
   * @param revReq Request
   * @return the IssuerDN
   */
  private String getIssuerDNFromRevRequest(final RevReqContent revReq) {
    RevDetails rd;
    try {
      rd = revReq.toRevDetailsArray()[0];
    } catch (Exception e) {
      LOG.debug(
          "Could not parse the revocation request. Trying to parse it as"
              + " novosec generated message.");
      rd = CmpMessageHelper.getNovosecRevDetails(revReq);
      LOG.debug("Succeeded in parsing the novosec generated request.");
    }
    final CertTemplate ct = rd.getCertDetails();
    final X500Name issuer = ct.getIssuer();
    if (issuer != null) {
      return ct.getIssuer().toString();
    }
    return "";
  }

  /**
   * Return the ID of the CA that is used for CMP purposes.
   *
   * @param keyId ID
   * @param eep Profile
   * @return the ID of CA used for CMP purposes.
   */
  private int getRaCaId(
      final DEROctetString keyId, final EndEntityProfile eep) {

    String caname = this.cmpConfiguration.getRACAName(this.confAlias);
    if (StringUtils.equals(caname, CmpConfiguration.PROFILE_DEFAULT)) {
      final int caid = eep.getDefaultCA();
      if (LOG.isDebugEnabled()) {
        LOG.debug("Using EndEntity profile's default CA with ID: " + caid);
      }
      return caid;
    }

    if (StringUtils.equals(caname, CmpConfiguration.PROFILE_USE_KEYID)
        && (keyId != null)) {
      caname = CmpMessageHelper.getStringFromOctets(keyId);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Using CA with same name as KeyId in request: " + caname);
      }
    }
    return getCAInfoByName(caname).getCAId();
  }

  private CertificateProfile getCertificateProfileFromCrmf(
      final EndEntityProfile eep, final DEROctetString keyId) {
    CertificateProfile profile = null;
    String cpname = this.cmpConfiguration.getRACertProfile(this.confAlias);
    if (StringUtils.equals(cpname, CmpConfiguration.PROFILE_DEFAULT)) {
      final int cpid = eep.getDefaultCertificateProfile();
      profile = certProfileSession.getCertificateProfile(cpid);
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Using EndEntityProfile's default CertificateProfile: " + cpid);
      }
    } else if (StringUtils.equals(cpname, CmpConfiguration.PROFILE_USE_KEYID)
        && (keyId != null)) {
      cpname = CmpMessageHelper.getStringFromOctets(keyId);
      profile = certProfileSession.getCertificateProfile(cpname);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Using CertificateProfile specified as 'KeyId': " + cpname);
      }
    } else {
      profile = certProfileSession.getCertificateProfile(cpname);
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Using CertificateProfile as specified in the CMP alias: "
                + cpname);
      }
    }
    return profile;
  }

  private boolean isCertificateProfileAuthorizedToCA(
      final CertificateProfile profile, final int caid) {
    // Check that CAid is among available CAs
    boolean caauthorized = false;
    if (profile != null) {
      for (final Integer availablecas : profile.getAvailableCAs()) {
        final int availableca = availablecas.intValue();
        if (availableca == caid || availableca == CertificateProfile.ANYCA) {
          caauthorized = true;
          break;
        }
      }
    } else {
      LOG.info("CMP CertificateProfile not found");
    }
    return caauthorized;
  }

  /**
   * Checks that the extracerts is a valid certificate path, that verifies up to
   * the TrustAnchor being the Root CA certificate of the supplied CA.
   *
   * @param extracerts certificates from the extraCerts field from the CMP
   *     Message
   * @param cainfo The CA we want to verify extraCerts with, can be a root CA or
   *     a sub CA, in which case the sub CA's root CA is used as trust anchor
   * @return true if extracert(s) verifies up to the trust anchor, false
   *     otherwise
   */
  private boolean isExtraCertValidAndIssuedByCA(
      final List<X509Certificate> extracerts, final CAInfo cainfo) {
    if (extracerts == null || extracerts.isEmpty()) {
      throw new IllegalArgumentException(
          "extracerts must contain a certificate.");
    }
    Certificate endentitycert = null;
    try {
      // What we got in extraCerts can be different things
      // - An end entity certificate only, signed by a SubCA or a RootCA
      // -- We need to find both SubCA and RootCA here, should be in cainfo?
      // - An end entity certificate and a SubCA certificate
      // -- We need to find the RootCA certificate only, should be in cainfo?
      // - An end entity certificate a SubCA certificate and a RootCA
      // certificate
      // -- We need to remove the CA certificates that are not part of cainfo
      ArrayList<Certificate> certlist = new ArrayList<>();
      // Create CertPath
      certlist.addAll(extracerts);
      // Move CA certificates into cert path, except root certificate which is
      // the trust anchor
      X509Certificate rootcert = null;
      Collection<Certificate> trustedCertificates =
          cainfo.getCertificateChain();
      final Iterator<Certificate> itr = trustedCertificates.iterator();
      while (itr.hasNext()) {
        // Trust anchor is last, so if this is the last element, don't add it
        Certificate crt = itr.next();
        if (itr.hasNext()) {
          if (!certlist.contains(crt)) {
            certlist.add(crt);
          } else {
            if (LOG.isDebugEnabled()) {
              LOG.debug(
                  "Certlist already contains certificate with subject "
                      + CertTools.getSubjectDN(crt)
                      + ", not adding to list");
            }
          }
        } else {
          rootcert = (X509Certificate) crt;
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Using certificate with subject "
                    + CertTools.getSubjectDN(crt)
                    + ", as trust anchor, removing from certlist if it is"
                    + " there");
          }
          // Don't have the trust anchor in the cert path, remove doesn't do
          // anything if rootcert doesn't exist in certlist
          certlist.remove(rootcert);
        }
      }
      CertPath cp =
          CertificateFactory.getInstance(
                  "X.509", BouncyCastleProvider.PROVIDER_NAME)
              .generateCertPath(certlist);
      // The end entity cert is the first one in the CertPath according to
      // javadoc
      // - "By convention, X.509 CertPaths (consisting of X509Certificates), are
      // ordered starting with the target
      //    certificate and ending with a certificate issued by the trust
      // anchor.
      //    That is, the issuer of one certificate is the subject of the
      // following one."
      // Note: CertPath above will most likely not sort the path, at least if
      // there is a root cert in certlist
      // the cp will fail verification if it was not in the right order in
      // certlist to start with
      endentitycert = cp.getCertificates().get(0);
      TrustAnchor anchor = new TrustAnchor(rootcert, null);
      PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
      params.setRevocationEnabled(false);
      CertPathValidator cpv =
          CertPathValidator.getInstance(
              "PKIX", BouncyCastleProvider.PROVIDER_NAME);
      PKIXCertPathValidatorResult result =
          (PKIXCertPathValidatorResult) cpv.validate(cp, params);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Certificate verify result: " + result.toString());
      }
      // No CertPathValidatorException thrown means it passed
      return true;
    } catch (CertPathValidatorException e) {
      this.errorMessage =
          "The certificate attached to the PKIMessage in the extraCert field"
              + " is not valid - "
              + getCertPathValidatorExceptionMessage(e);
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            this.errorMessage
                + ": SubjectDN="
                + CertTools.getSubjectDN(endentitycert));
      }
    } catch (CertificateException e) {
      LOG.warn("CertificateException", e);
    } catch (NoSuchProviderException e) {
      // Serious error, bail out
      LOG.error("NoSuchProviderException", e);
      throw new IllegalStateException(e);
    } catch (InvalidAlgorithmParameterException e) {
      LOG.info("InvalidAlgorithmParameterException", e);
    } catch (NoSuchAlgorithmException e) {
      LOG.info("NoSuchAlgorithmException", e);
    }
    return false;
  }

  /**
   * Returns the message from a CertPathValidatorException. For the common
   * cases, this method is locale independent.
   *
   * @param e Exception
   * @return Message
   */
  private String getCertPathValidatorExceptionMessage(
      final CertPathValidatorException e) {
    Certificate endEntityCert = null;
    if (e.getCertPath() != null
        && CollectionUtils.isNotEmpty(e.getCertPath().getCertificates())) {
      endEntityCert = e.getCertPath().getCertificates().get(0);
    }
    // getReason returns BasicReason.UNSPECIFIED for expired or not yet valid
    // certs, so we need to look at the cause.
    final Throwable cause = e.getCause();
    if (cause instanceof CertificateExpiredException) {
      return "Certificate has expired. NotAfter: "
          + ValidityDate.formatAsUTC(CertTools.getNotAfter(endEntityCert))
          + " UTC";
    } else if (cause instanceof CertificateNotYetValidException) {
      return "Certificate is not yet valid. NotBefore: "
          + ValidityDate.formatAsUTC(CertTools.getNotBefore(endEntityCert))
          + " UTC";
    } else {
      return e.getMessage();
    }
  }

  private boolean isExtraCertActive(final CertificateInfo certinfo) {
    // CERT_NOTIFIEDABOUTEXPIRATION is also active...
    if (certinfo.getStatus() != CertificateConstants.CERT_ACTIVE
        && certinfo.getStatus()
            != CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION) {
      this.errorMessage =
          "The certificate attached to the PKIMessage in the extraCert field"
              + " is not active.";
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            this.errorMessage
                + " Username="
                + certinfo.getUsername()
                + ", fingerprint="
                + certinfo.getFingerprint());
      }
      return false;
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("The certificate in extraCert is active");
    }
    return true;
  }

  private CAInfo getCAInfoByName(final String caname) {
    try {
      return caSession.getCAInfo(admin, caname);
    } catch (AuthorizationDeniedException e) {
      this.errorMessage = "Authorization denied for CA: " + caname;
      if (LOG.isDebugEnabled()) {
        LOG.debug(this.errorMessage + " - " + e.getLocalizedMessage());
      }
    }
    return null;
  }

  private CAInfo getCAInfoByIssuer(final String issuerDN) {
    try {
      return caSession.getCAInfo(admin, issuerDN.hashCode());
    } catch (AuthorizationDeniedException e) {
      this.errorMessage = "Authorization denied for CA: " + issuerDN;
      if (LOG.isDebugEnabled()) {
        LOG.debug(this.errorMessage + " - " + e.getLocalizedMessage());
      }
    }
    return null;
  }
}
