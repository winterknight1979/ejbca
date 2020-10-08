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

package org.ejbca.ui.cli.ca;

import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.keys.token.BaseCryptoToken;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Renews the CA certificate and optionally regenerates the key pair. This is the CLI equivalent of pushing 
 * the renewal button in EJBCA Admin Web.
 *
 * @version $Id: CaRenewCACommand.java 28491 2018-03-16 08:19:42Z anatom $
 */
public class CaRenewCACommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaRenewCACommand.class);

    private static final String NEWLINE = System.getProperty("line.separator");

    private static final String CA_NAME_KEY = "--caname";
    private static final String REGENERATE_KEYS_KEY = "-R";
    private static final String AUTHORIZATION_CODE_KEY = "--auth";
    private static final String CUSTOM_NOT_BEFORE_KEY = "--notbefore";
    private static final String EXPLICIT_ECC_KEY = "-explicitecc";

    {
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of the CA"));
        registerParameter(Parameter.createFlag(REGENERATE_KEYS_KEY, "Set this switch if the CA's keys are to be regenerated."));
        registerParameter(new Parameter(AUTHORIZATION_CODE_KEY, "Authorization Code", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Authorization code is only used when changing -expliciecc property on a Crypto Token. If setting 'explicitecc' on a Crypto Token and this parameter is not set then user will be prompted."));
        registerParameter(new Parameter(CUSTOM_NOT_BEFORE_KEY, "Date", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Set this value of a value other than current time should be used. Must be in ISO 8601 format, for example '2010-09-08 07:06:05+02:00"));
        registerParameter(Parameter.createFlag(EXPLICIT_ECC_KEY, "Adding the switch '" + EXPLICIT_ECC_KEY
                + "' when using ECC keys makes the internal Crypto Token use explicit curve parameters instead of named curves. "
                + "Should only be used when renewing a CSCA for ePassports, and it will persist in the Crypto Token for future renewals."));
    }

    private SimpleDateFormat simpleDateFormat = null;

    private SimpleDateFormat getSimpleDateFormat() {
        if (simpleDateFormat == null) {
            simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZZ");
        }
        return simpleDateFormat;
    }

    @Override
    public String getMainCommand() {
        return "renewca";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {

        // Bouncy Castle security provider
        CryptoProviderTools.installBCProvider();

        // Get the CAs info and id
        final String caname = parameters.get(CA_NAME_KEY);
        CAInfo cainfo;
        try {
            cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caname);
            boolean regenerateKeys = false;
            Date customNotBefore = null;
            regenerateKeys = parameters.containsKey(REGENERATE_KEYS_KEY);
            String authCode = parameters.get(AUTHORIZATION_CODE_KEY);
            if (parameters.get(CUSTOM_NOT_BEFORE_KEY) != null) {
                try {
                    customNotBefore = ValidityDate.parseAsIso8601(parameters.get(CUSTOM_NOT_BEFORE_KEY));
                    if (customNotBefore == null) {
                        getLogger().error("ERROR: Could not parse date. Use ISO 8601 format, for example '2010-09-08 07:06:05+02:00' ");
                        return CommandResult.FUNCTIONAL_FAILURE;
                    }
                } catch (ParseException e) {
                    getLogger().error("ERROR: " + e.getMessage() + ". Use ISO 8601 format, for example '2010-09-08 07:06:05+02:00' ");
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
            }

            final StringBuilder buff = new StringBuilder();
            buff.append("Renew CA ");
            buff.append(caname);
            buff.append(" ");
            if (regenerateKeys) {
                buff.append("with a new key pair");
            } else {
                buff.append("with the current key pair");
            }
            if (customNotBefore != null) {
                buff.append(" and with custom notBefore date: ");
                buff.append(getSimpleDateFormat().format(customNotBefore));
            }
            getLogger().info(buff.toString());

            getLogger().info("Current certificate: ");
            final Object oldCertificate = cainfo.getCertificateChain().iterator().next();
            if (oldCertificate instanceof Certificate) {
                printCertificate((Certificate) oldCertificate);
            } else {
                getLogger().error("Error: Certificate not found");
            }

            final String explicitEcc = (parameters.get(EXPLICIT_ECC_KEY) != null ? Boolean.TRUE.toString() : Boolean.FALSE.toString());
            if (StringUtils.equalsIgnoreCase(explicitEcc, "true")) {
                // Set if we should use explicit ECC parameters of not. On Java 6 this renders the created CA certificate not serializable
                getLogger().info("Explicit ECC public key parameters: " + explicitEcc);
                final int cryptoTokenId = cainfo.getCAToken().getCryptoTokenId();
                final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
                final CryptoTokenInfo tokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(getAuthenticationToken(), cryptoTokenId);
                Properties cryptoTokenProperties = tokenInfo.getCryptoTokenProperties();
                if (cryptoTokenProperties.get(BaseCryptoToken.EXPLICIT_ECC_PUBLICKEY_PARAMETERS) == null) {
                    getLogger().info("Explicit ECC public key parameters is not enabled for Crypto Token with ID: " + cryptoTokenId+", changing Crypto Token to enable it.");
                    getLogger().info("Password: '"+authCode+"'");
                    if (authCode == null) {
                        getLogger().info("Enter Crypto Token authentication code to continue: ");
                        authCode = String.valueOf(System.console().readPassword());
                    }
                    cryptoTokenProperties.setProperty(CryptoToken.EXPLICIT_ECC_PUBLICKEY_PARAMETERS, explicitEcc);
                    cryptoTokenManagementSession.saveCryptoToken(getAuthenticationToken(), cryptoTokenId, tokenInfo.getName(), cryptoTokenProperties, authCode.toCharArray());
                } else {
                    getLogger().info("Explicit ECC public key parameters already enabled for Crypto Token with ID: " + cryptoTokenId+", leaving Crypto Token untouched.");                    
                }
            }

            try {
                EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class).renewCA(getAuthenticationToken(), cainfo.getCAId(),
                        regenerateKeys, customNotBefore, regenerateKeys);
            } catch (CryptoTokenOfflineException e) {
                log.error("ERROR: Could not create keys, crypto token was unavailable: " + e.getMessage());
            }
            getLogger().info("New certificate created:");
            cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caname);
            if (cainfo == null) {
                log.error("CA of name " + caname + " does not exist.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }

            final Object newCertificate = cainfo.getCertificateChain().iterator().next();
            if (newCertificate instanceof Certificate) {
                printCertificate((Certificate) newCertificate);
                return CommandResult.SUCCESS;
            } else {
                getLogger().error("ERROR: Certificate not found");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        } catch (AuthorizationDeniedException e1) {
            log.error("ERROR: Current CLI user isn't authorized to renew CA " + caname);
            return CommandResult.AUTHORIZATION_FAILURE;
        } catch (CADoesntExistsException e) {
            log.error("ERROR: No CA of name " + caname + " exists.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (CryptoTokenOfflineException e) {
            log.error("ERROR: Crypto Token is off-line for CA: " + caname);
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (CryptoTokenAuthenticationFailedException e) {
            log.error("ERROR: Invalid Crypto Token authentication code for CA: " + caname);
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (CryptoTokenNameInUseException e) {
            log.error("ERROR: Crypto Token name collision for CA: " + caname+". This should not be possible to happen.");
            log.error("Exception: ", e);
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (NoSuchSlotException e) {
            log.error("ERROR: Existing Crypto Token claims the slot is not available. Check the Crypto Token for CA: " + caname);
            log.error("Error message: "+e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        }

    }

    @Override
    public String getCommandDescription() {
        return "Renew CA certificate and optionally regenerate keys";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    private void printCertificate(final Certificate certificate) {
        if (certificate instanceof X509Certificate) {
            final X509Certificate x509 = (X509Certificate) certificate;
            getLogger().info(
                    new StringBuilder().append("  Serial number:  ").append(x509.getSerialNumber().toString(16)).append(NEWLINE)
                            .append("  Issuer DN:      ").append(x509.getIssuerDN().getName()).append(NEWLINE).append("  Subject DN:     ")
                            .append(x509.getSubjectDN().getName()).append(NEWLINE).append("  Not Before:     ")
                            .append(getSimpleDateFormat().format(x509.getNotBefore())).append(NEWLINE).append("  Not After:      ")
                            .append(getSimpleDateFormat().format(x509.getNotAfter())).append(NEWLINE).append("  Subject key id: ")
                            .append(computeSubjectKeyIdentifier(x509)).append(NEWLINE).toString());
        } else if (certificate instanceof CardVerifiableCertificate) {
            final CardVerifiableCertificate cvc = (CardVerifiableCertificate) certificate;
            try {
                getLogger().info(
                        new StringBuilder().append("  ").append(cvc.getCVCertificate().getCertificateBody().getHolderReference().getAsText(false))
                                .append(NEWLINE).append("  ")
                                .append(cvc.getCVCertificate().getCertificateBody().getAuthorityReference().getAsText(false)).append(NEWLINE)
                                .append("  Not Before:      ")
                                .append(getSimpleDateFormat().format(cvc.getCVCertificate().getCertificateBody().getValidFrom())).append(NEWLINE)
                                .append("  Not After:       ")
                                .append(getSimpleDateFormat().format(cvc.getCVCertificate().getCertificateBody().getValidTo())).append(NEWLINE)
                                .append("  Public key hash: ").append(computePublicKeyHash(cvc.getPublicKey())).append(NEWLINE).toString());
            } catch (NoSuchFieldException ex) {
                getLogger().error("Error: Could not read field in CV Certificate: " + ex.getMessage());
            }
        } else {
            getLogger().info(new StringBuilder().append("  Unknown certificate type:").append(NEWLINE).append(certificate.toString()).toString());
        }
    }

    private static String computeSubjectKeyIdentifier(final X509Certificate certificate) {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(certificate.getPublicKey().getEncoded());
        X509ExtensionUtils utils = new X509ExtensionUtils(SHA1DigestCalculator.buildSha1Instance());
        SubjectKeyIdentifier ski = utils.createSubjectKeyIdentifier(spki);
        return new String(Hex.encode(ski.getKeyIdentifier()));
    }

    private static String computePublicKeyHash(final PublicKey publicKey) {
        final Digest digest = new SHA1Digest();
        final byte[] hash = new byte[digest.getDigestSize()];
        final byte[] data = publicKey.getEncoded();
        digest.update(data, 0, data.length);
        digest.doFinal(hash, 0);
        return new String(Hex.encode(hash));
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
}
