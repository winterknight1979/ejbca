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

package org.ejbca.core.protocol.scep;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.Base64Util;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.protocol.NoSuchAliasException;
import org.ejbca.ui.web.protocol.CertificateRenewalException;

/**
 * @version $Id: ScepMessageDispatcherSessionBean.java 28857 2018-05-07
 *     08:35:30Z samuellb $
 */
@Stateless(
    mappedName =
        JndiConstants.APP_JNDI_PREFIX + "ScepMessageDispatcherSessionRemote")
public class ScepMessageDispatcherSessionBean
    implements ScepMessageDispatcherSessionLocal,
        ScepMessageDispatcherSessionRemote {

  /** Internal localization of logs and errors. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();

  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(ScepMessageDispatcherSessionBean.class);

  /** Param. */
  private static final String SCEP_RA_MODE_EXTENSION_CLASSNAME =
      "org.ejbca.core.protocol.scep.ScepRaModeExtension";
  /** Param. */
  private static final String SCEP_CLIENT_CERTIFICATE_RENEWAL_CLASSNAME =
      "org.ejbca.core.protocol.scep.ClientCertificateRenewalExtension";

  /** Param. */
  private transient ScepOperationPlugin scepRaModeExtension = null;
  /** Param. */
  private transient ScepResponsePlugin scepClientCertificateRenewal = null;

  /** EJB. */
  @EJB private GlobalConfigurationSessionLocal globalConfigSession;
  /** EJB. */
  @EJB private SignSessionLocal signSession;
  /** EJB. */
  @EJB private CaSessionLocal caSession;

  /** Init. */
  @PostConstruct
  public void postConstruct() {
    try {
      @SuppressWarnings("unchecked")
      Class<? extends ScepOperationPlugin> extensionClass =
          (Class<? extends ScepOperationPlugin>)
              Class.forName(SCEP_RA_MODE_EXTENSION_CLASSNAME);
      scepRaModeExtension = extensionClass.getConstructor().newInstance();
    } catch (ClassNotFoundException | NoSuchMethodException e) {
      scepRaModeExtension = null;
    } catch (InstantiationException | InvocationTargetException e) {
      scepRaModeExtension = null;
      LOG.error(
          SCEP_RA_MODE_EXTENSION_CLASSNAME
              + " was found, but could not be instanced. "
              + e.getMessage());
    } catch (IllegalAccessException e) {
      scepRaModeExtension = null;
      LOG.error(
          SCEP_RA_MODE_EXTENSION_CLASSNAME
              + " was found, but could not be instanced. "
              + e.getMessage());
    }

    try {
      @SuppressWarnings("unchecked")
      Class<ScepResponsePlugin> extensionClass =
          (Class<ScepResponsePlugin>)
              Class.forName(SCEP_CLIENT_CERTIFICATE_RENEWAL_CLASSNAME);
      scepClientCertificateRenewal =
          extensionClass.getConstructor().newInstance();
    } catch (ClassNotFoundException | NoSuchMethodException e) {
      scepClientCertificateRenewal = null;
    } catch (InstantiationException | InvocationTargetException e) {
      scepClientCertificateRenewal = null;
      LOG.error(
          SCEP_CLIENT_CERTIFICATE_RENEWAL_CLASSNAME
              + " was found, but could not be instanced. "
              + e.getMessage());
    } catch (IllegalAccessException e) {
      scepClientCertificateRenewal = null;
      LOG.error(
          SCEP_CLIENT_CERTIFICATE_RENEWAL_CLASSNAME
              + " was found, but could not be instanced. "
              + e.getMessage());
    }
  }

  @Override
  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  public byte[] dispatchRequest(
      final AuthenticationToken authenticationToken,
      final String operation,
      final String message,
      final String scepConfigurationAlias)
      throws NoSuchAliasException, CADoesntExistsException,
          AuthorizationDeniedException, NoSuchEndEntityException,
          CustomCertificateSerialNumberException, CryptoTokenOfflineException,
          IllegalKeyException, SignRequestException,
          SignRequestSignatureException, AuthStatusException,
          AuthLoginException, IllegalNameException, CertificateCreateException,
          CertificateRevokeException, CertificateSerialNumberException,
          IllegalValidityException, CAOfflineException,
          InvalidAlgorithmException, SignatureException, CertificateException,
          CertificateExtensionException, CertificateRenewalException {

    ScepConfiguration scepConfig =
        (ScepConfiguration)
            this.globalConfigSession.getCachedConfiguration(
                ScepConfiguration.SCEP_CONFIGURATION_ID);
    if (!scepConfig.aliasExists(scepConfigurationAlias)) {
      throw new NoSuchAliasException();
    }

    if (operation.equals("PKIOperation")) {
      byte[] scepmsg = Base64Util.decode(message.getBytes());
      // Read the message and get the certificate, this also checks
      // authorization
      return scepCertRequest(
          authenticationToken, scepmsg, scepConfigurationAlias, scepConfig);
    } else if (operation.equals("GetCACert")) {
      // CA_IDENT is the message for this request to indicate which CA we are
      // talking about
      final String caname = getCAName(message);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Got SCEP cert request for CA '" + caname + "'");
      }
      Collection<Certificate> certs = null;
      CAInfo cainfo = caSession.getCAInfoInternal(-1, caname, true);
      if (cainfo != null) {
        certs = cainfo.getCertificateChain();
      }
      if ((certs != null) && (certs.size() > 0)) {
        // CAs certificate is in the first position in the Collection
        X509Certificate cert = (X509Certificate) certs.iterator().next();
        if (LOG.isDebugEnabled()) {
          LOG.debug("Sent certificate for CA '" + caname + "' to SCEP client.");
        }
        return cert.getEncoded();
      } else {
        return null;
      }
    } else if (operation.equals("GetCACertChain")) {
      // CA_IDENT is the message for this request to indicate which CA we are
      // talking about
      final String caname = getCAName(message);
      LOG.debug(
          "Got SCEP pkcs7 request for CA '"
              + caname
              + "'. Old client using SCEP draft 18?");

      CAInfo cainfo = caSession.getCAInfo(authenticationToken, caname);
      byte[] pkcs7 =
          signSession.createPKCS7(authenticationToken, cainfo.getCAId(), true);
      if ((pkcs7 != null) && (pkcs7.length > 0)) {
        return pkcs7;
      } else {
        return null;
      }
    } else if (operation.equals("GetNextCACert")) {
      final String caname = getCAName(message);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Got SCEP next cert request for CA '" + caname + "'");
      }
      final CAInfo cainfo = caSession.getCAInfoInternal(-1, caname, true);
      if (cainfo == null) {
        String errMsg =
            INTRES.getLocalizedMessage("scep.errorunknownca", "cert");
        LOG.error(errMsg);
        throw new CADoesntExistsException(errMsg);
      } else {
        if (caSession.getFutureRolloverCertificate(cainfo.getCAId()) != null) {
          // Send full certificate chain of next CA, in SCEP-PKCS7 format
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Sending next certificate chain for CA '"
                    + caname
                    + "' to SCEP client.");
          }
          return signSession.createPKCS7Rollover(
              authenticationToken, cainfo.getCAId());
        } else {
          return null;
        }
      }
    } else if (operation.equals("GetCACaps")) {
      final String caname = getCAName(message);
      final CAInfo cainfo = caSession.getCAInfoInternal(-1, caname, true);
      if (cainfo != null) {
        final boolean hasRolloverCert =
            (caSession.getFutureRolloverCertificate(cainfo.getCAId()) != null);
        // SCEP draft 23, "4.6.1.  Get Next CA Response Message Format".
        // It SHOULD also remove the GetNextCACert setting from the capabilities
        // until it does have rollover certificates.
        return hasRolloverCert
            ? "POSTPKIOperation\nGetNextCACert\nRenewal\nSHA-1".getBytes()
            : "POSTPKIOperation\nRenewal\nSHA-1".getBytes();
      } else {
        final String msg = "CA was not found: " + caname;
        LOG.debug(msg);
        throw new CADoesntExistsException(msg);
      }
    } else {
      LOG.error("Invalid parameter '" + operation);
    }
    return null;
  }

  /**
   * Later SCEP draft say that for GetCACert message is optional. If message is
   * there, it is the CA name but if message is not provided by the client, some
   * default CA should be used.
   *
   * @param message the message part for the SCEP get request, can be null or
   *     empty string
   * @return the message parameter or the default CA from ALIAS.defaultca
   *     property if message is null or empty.
   */
  private String getCAName(final String message) {
    // If message is a string, return it, but if message is empty return default
    // CA
    if (StringUtils.isEmpty(message)) {
      return EjbcaConfiguration.getScepDefaultCA();
    }
    return message;
  }

  /**
   * Handles SCEP certificate request.
   *
   * @param administrator Admin
   * @param msg buffer holding the SCEP-request (DER encoded).
   * @param alias the alias of the SCEP configuration
   * @param scepConfig The SCEP configuration
   * @return byte[] containing response to be sent to client.
   * @throws AuthorizationDeniedException Fail
   * @throws CertificateExtensionException if msg specified invalid extensions
   * @throws InvalidAlgorithmException Fail
   * @throws CAOfflineException Fail
   * @throws IllegalValidityException Fail
   * @throws CertificateSerialNumberException Fail
   * @throws CertificateRevokeException Fail
   * @throws CertificateCreateException Fail
   * @throws IllegalNameException Fail
   * @throws AuthLoginException Fail
   * @throws AuthStatusException Fail
   * @throws SignRequestSignatureException Fail
   * @throws SignRequestException Fail
   * @throws CADoesntExistsException Fail
   * @throws IllegalKeyException Fail
   * @throws CryptoTokenOfflineException Fail
   * @throws CustomCertificateSerialNumberException Fail
   * @throws CertificateRenewalException if an error occurs during Client
   *     Certificate Renewal
   * @throws SignatureException if a Client Certificate Renewal request was
   *     badly signed.
   * @throws CertificateException Fail
   * @throws NoSuchEndEntityException if end entity wasn't found, and RA mode
   *     isn't available.
   */
  private byte[] scepCertRequest(
      final AuthenticationToken administrator,
      final byte[] msg,
      final String alias,
      final ScepConfiguration scepConfig)
      throws AuthorizationDeniedException, CertificateExtensionException,
          NoSuchEndEntityException, CustomCertificateSerialNumberException,
          CryptoTokenOfflineException, IllegalKeyException,
          CADoesntExistsException, SignRequestException,
          SignRequestSignatureException, AuthStatusException,
          AuthLoginException, IllegalNameException, CertificateCreateException,
          CertificateRevokeException, CertificateSerialNumberException,
          IllegalValidityException, CAOfflineException,
          InvalidAlgorithmException, CertificateRenewalException,
          SignatureException, CertificateException {
    byte[] ret = null;
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getRequestMessage(" + msg.length + " bytes)");
    }

    try {
      boolean includeCACert = scepConfig.getIncludeCA(alias);
      final ScepRequestMessage reqmsg =
          new ScepRequestMessage(msg, includeCACert);
      boolean isRAModeOK = scepConfig.getRAMode(alias);

      if (reqmsg.getErrorNo() != 0) {
        LOG.error(
            "Error '"
                + reqmsg.getErrorNo()
                + "' receiving Scep request message.");
        return null;
      }
      if (reqmsg.getMessageType() == ScepRequestMessage.SCEP_TYPE_PKCSREQ) {
        if (isRAModeOK && scepRaModeExtension == null) {
          // Fail nicely
          LOG.warn(
              "SCEP RA mode is enabled, but not included in the community"
                  + " version of EJBCA. Unable to continue.");
          return null;
        } else if (isRAModeOK) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("SCEP is operating in RA mode: " + isRAModeOK);
          }
          if (!scepRaModeExtension.performOperation(
              administrator, reqmsg, scepConfig, alias)) {
            String errmsg =
                "Error. Failed to add or edit user: " + reqmsg.getUsername();
            LOG.error(errmsg);
            return null;
          }
        }
        if (scepClientCertificateRenewal != null
            && scepConfig.getClientCertificateRenewal(alias)) {
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "SCEP client certificate renewal/enrollment with alias '"
                    + alias
                    + "'");
          }
          ResponseMessage resp =
              scepClientCertificateRenewal.performOperation(
                  administrator, reqmsg, scepConfig, alias);
          if (resp != null) {
            ret = resp.getResponseMessage();
          }
        } else {
          // Get the certificate
          if (LOG.isDebugEnabled()) {
            LOG.debug("SCEP certificate enrollment with alias '" + alias + "'");
          }
          ResponseMessage resp =
              signSession.createCertificate(
                  administrator, reqmsg, ScepResponseMessage.class, null);
          if (resp != null) {
            ret = resp.getResponseMessage();
          }
        }
      }
      if (reqmsg.getMessageType() == ScepRequestMessage.SCEP_TYPE_GETCRL) {
        // create the stupid encrypted CRL message, the below can actually only
        // be made
        // at the CA, since CAs private key is needed to decrypt
        ResponseMessage resp =
            signSession.getCRL(
                administrator, reqmsg, ScepResponseMessage.class);
        if (resp != null) {
          ret = resp.getResponseMessage();
        }
      }
    } catch (IOException e) {
      LOG.error("Error receiving ScepMessage: ", e);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<getRequestMessage():" + ((ret == null) ? 0 : ret.length));
    }
    return ret;
  }
}
