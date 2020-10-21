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

package org.ejbca.core.model.ca.publisher;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPJSSEStartTLSFactory;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import java.io.UnsupportedEncodingException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.Extension;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.util.LdapNameStyle;
import org.ejbca.util.LdapTools;
import org.ejbca.util.TCPTool;

/**
 * LdapPublisher is a class handling a publishing to various v3 LDAP catalogs.
 *
 * @version $Id: LdapPublisher.java 34192 2020-01-07 15:10:21Z aminkh $
 */
public class LdapPublisher extends BasePublisher {

  private static final long serialVersionUID = -584431431033065114L;
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(LdapPublisher.class);
  /** Internal localization of logs and errors. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();

  /** Version. */
  public static final float LATEST_VERSION = 12;

  // Create some constraints used when connecting, disconnecting, reading and
  // storing in LDAP servers
  /** Use a time limit for generic (non overridden) LDAP operations. */
  protected LDAPConstraints ldapConnectionConstraints = new LDAPConstraints();
  /** Use a time limit for LDAP bind operations. */
  protected LDAPConstraints ldapBindConstraints = new LDAPConstraints();
  /** Use a time limit for LDAP store operations. */
  protected LDAPConstraints ldapStoreConstraints = new LDAPConstraints();
  /** Use a time limit for LDAP disconnect operations. */
  protected LDAPConstraints ldapDisconnectConstraints = new LDAPConstraints();
  /** Use a time limit when reading from LDAP. */
  protected LDAPSearchConstraints ldapSearchConstraints =
      new LDAPSearchConstraints();

  /**
   * The normal ldap publisher will modify attributes in LDAP. If you don't want
   * attributes modified, use the LdapSearchPublisher to store certificates in
   * already existing entries. Can be overridden in constructor of subclasses.
   */
  protected boolean addModificationAttributes = true;

  public enum ConnectionSecurity {
      /** Unencrypted. */
    PLAIN,
    /** START-TLS. */
    STARTTLS,
    /** SSL. */
    SSL
  }

  /** Config. */
  public static final String DEFAULT_USEROBJECTCLASS =
      "top;person;organizationalPerson;inetOrgPerson";
  /** Config. */
  public static final String DEFAULT_CAOBJECTCLASS =
      "top;applicationProcess;certificationAuthority-V2";
  /** Config. */
  public static final String DEFAULT_CACERTATTRIBUTE = "cACertificate;binary";
  /** Config. */
  public static final String DEFAULT_USERCERTATTRIBUTE =
      "userCertificate;binary";
  /** Config. */
  public static final String DEFAULT_CRLATTRIBUTE =
      "certificateRevocationList;binary";
  /** Config. */
  public static final String DEFAULT_DELTACRLATTRIBUTE =
      "deltaRevocationList;binary";
  /** Config. */
  public static final String DEFAULT_ARLATTRIBUTE =
      "authorityRevocationList;binary";
  /** Config. */
  public static final String DEFAULT_PORT = "389";
  /** Config. */
  public static final String DEFAULT_SSLPORT = "636";
  /** Config. */
  public static final String DEFAULT_TIMEOUT = "5000"; // 5 seconds
  /** Config. */
  public static final String DEFAULT_READTIMEOUT = "30000"; // 30 seconds
  /** Config. */
  public static final String DEFAULT_STORETIMEOUT = "60000"; // 1 minute
  // Default Values
  /** Config. */
  protected static final String HOSTNAMES = "hostname";
  /** Config. */
  protected static final String CONNECTIONSECURITY = "connectionsecurity";

  // USESSL was removed in v12, but is kept for backwards compatibility
  /** Config. */
  protected static final String USESSL = "usessl";
  /** Config. */
  protected static final String PORT = "port";
  /** Config. */
  protected static final String BASEDN = "baswdn";
  /** Config. */
  protected static final String LOGINDN = "logindn";
  /** Config. */
  public static final String LOGINPASSWORD = "loginpassword";
  /** Config. */
  protected static final String TIMEOUT = "timeout";
  /** Config. */
  protected static final String READTIMEOUT = "readtimeout";
  /** Config. */
  protected static final String STORETIMEOUT = "storetimeout";
  /** Config. */
  protected static final String CREATENONEXISTING = "createnonexisting";
  /** Config. */
  protected static final String MODIFYEXISTING = "modifyexisting";
  /** Config. */
  protected static final String ADDNONEXISTINGATTR = "addnonexistingattr";
  /** Config. */
  protected static final String MODIFYEXISTINGATTR = "modifyexistingattr";
  /** Config. */
  protected static final String USEROBJECTCLASS = "userobjectclass";
  /** Config. */
  protected static final String CAOBJECTCLASS = "caobjectclass";
  /** Config. */
  protected static final String USERCERTATTRIBUTE = "usercertattribute";
  /** Config. */
  protected static final String CACERTATTRIBUTE = "cacertattribute";
  /** Config. */
  protected static final String CRLATTRIBUTE = "crlattribute";
  /** Config. */
  protected static final String DELTACRLATTRIBUTE = "deltacrlattribute";
  /** Config. */
  protected static final String ARLATTRIBUTE = "arlattribute";
  /** Config. */
  protected static final String USEFIELDINLDAPDN = "usefieldsinldapdn";
  /** Config. */
  protected static final String ADDMULTIPLECERTIFICATES =
      "addmultiplecertificates";
  /** Config. */
  protected static final String REMOVEREVOKED = "removerevoked";
  /** Config. */
  protected static final String REMOVEUSERONCERTREVOKE =
      "removeusersoncertrevoke";
  /** Config. */
  protected static final String CREATEINTERMEDIATENODES =
      "createintermediatenodes";
  /** Config. */
  protected static final String SETUSERPASSWORD = "setuserpasssword";

  /** Arrays used to extract attributes to store in LDAP. */
  protected static final String[] MATCHINGEXTRAATTRIBUTES = {"CN", "L", "OU"};

  /** Config. */
  protected static final String[] MATCHINGPERSONALATTRIBUTES = {
    "ST",
    "O",
    "uid",
    "initials",
    "title",
    "postalCode",
    "businessCategory",
    "postalAddress",
    "telephoneNumber"
  };

  /** Condtructor. */
  public LdapPublisher() {
    super();
    data.put(TYPE, Integer.valueOf(PublisherConst.TYPE_LDAPPUBLISHER));

    setHostnames("");
    setConnectionSecurity(ConnectionSecurity.STARTTLS);
    setPort(DEFAULT_PORT);
    setBaseDN("");
    setLoginDN("");
    setLoginPassword("");
    int connectiontimeout = getConnectionTimeOut();
    setConnectionTimeOut(connectiontimeout);
    setCreateNonExistingUsers(true);
    setModifyExistingUsers(true);
    setModifyExistingAttributes(false);
    setAddNonExistingAttributes(true);
    setUserObjectClass(DEFAULT_USEROBJECTCLASS);
    setCAObjectClass(DEFAULT_CAOBJECTCLASS);
    setUserCertAttribute(DEFAULT_USERCERTATTRIBUTE);
    setCACertAttribute(DEFAULT_CACERTATTRIBUTE);
    setCRLAttribute(DEFAULT_CRLATTRIBUTE);
    setDeltaCRLAttribute(DEFAULT_DELTACRLATTRIBUTE);
    setARLAttribute(DEFAULT_ARLATTRIBUTE);
    setUseFieldInLdapDN(new ArrayList<Integer>());
    // By default use only one certificate for each user
    setAddMultipleCertificates(false);
    setRemoveRevokedCertificates(true);
    setRemoveUsersWhenCertRevoked(false);
  }

  // Public Methods

  /**
   * Publishes certificate in LDAP, if the certificate is not revoked. If the
   * certificate is revoked, nothing is done and the publishing is counted as
   * successful (i.e. returns true).
   *@param admin admin
   * @param incert The certificate to be stored.
   * @param username Username of end entity owning the certificate.
   * @param password Password given to the user, may be null if no password
   *     exists for the user.
   * @param userDN if a DN object is not found in the certificate use object
   *     from user data instead, can be null.
   * @param cafp Fingerprint (hex) of the CAs certificate.
   * @param status Status of the certificate (from
   *     CertificateDataBean.CERT_ACTIVE, CERT_REVOKED etc).
   * @param type Type of certificate (from
   *     CertificateDataBean.CERTTYPE_ENDENTITY etc).
   * @param revocationDate Date for revocation (of revoked), like
   *     System.currentTimeMillis(), or -1 if not revoked.
   * @param revocationReason reason for revocation from RevokedCertInfo,
   *     RevokedCertInfo.NOT_REVOKED if not revoked.
   * @param tag TAg
   * @param certificateProfileId Profile
   * @param lastUpdate Date
   * @param extendedinformation contains extended information about the user,
   *     like picture, is null if no extendedinformation exists about the user.
   * @return true if storage was successful.
   * @throws PublisherException if a communication or other error occurs.
   * @see org.ejbca.core.model.ca.publisher.BasePublisher#storeCertificate
   */
  public boolean storeCertificate(
      final AuthenticationToken admin,
      final Certificate incert,
      final String username,
      final String password,
      final String userDN,
      final String cafp,
      final int status,
      final int type,
      final long revocationDate,
      final int revocationReason,
      final String tag,
      final int certificateProfileId,
      final long lastUpdate,
      final ExtendedInformation extendedinformation)
      throws PublisherException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">storeCertificate(username=" + username + ")");
    }

    if (status == CertificateConstants.CERT_REVOKED) {
      // Call separate script for revocation
      revokeCertificate(admin, incert, username, revocationReason, userDN);
    } else if (status == CertificateConstants.CERT_ACTIVE) {
      // Don't publish non-active certificates
      int ldapVersion = LDAPConnection.LDAP_V3;
      LDAPConnection lc = createLdapConnection();

      final String dn;
      final String certdn;
      try {
        // Extract the users DN from the cert.
        certdn = CertTools.getSubjectDN(incert);
        if (LOG.isDebugEnabled()) {
          LOG.debug("Constructing DN for: " + username);
        }
        dn = constructLDAPDN(certdn, userDN);
        if (LOG.isDebugEnabled()) {
          LOG.debug("LDAP DN for user " + username + " is '" + dn + "'");
        }
      } catch (Exception e) {
        String msg =
            INTRES.getLocalizedMessage(
                "publisher.errorldapdecode", "certificate");
        LOG.error(msg, e);
        throw new PublisherException(msg);
      }

      // Extract the users email from the cert.
      String email = CertTools.getEMailAddress(incert);

      // Check if the entry is already present, we will update it with the new
      // certificate.
      // To work well with the LdapSearchPublisher we need to pass the full
      // certificate DN to the
      // search function, and not only the LDAP DN. The regular publisher should
      // only use the LDAP DN though,
      // but the searchOldEntity function will take care of that.
      LDAPEntry oldEntry =
          searchOldEntity(username, ldapVersion, lc, certdn, userDN, email);

      // PART 2: Create LDAP entry
      LDAPEntry newEntry = null;
      ArrayList<LDAPModification> modSet = new ArrayList<LDAPModification>();
      LDAPAttributeSet attributeSet = null;
      String attribute = null;
      String objectclass = null;

      if (type == CertificateConstants.CERTTYPE_ENDENTITY) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Publishing end user certificate to first available server of "
                  + getHostnames());
        }
        if (oldEntry != null) {
          modSet =
              getModificationSet(
                  oldEntry,
                  certdn,
                  email,
                  addModificationAttributes,
                  true,
                  password,
                  incert);
        } else {
          objectclass = getUserObjectClass(); // just used for logging
          attributeSet =
              getAttributeSet(
                  incert,
                  getUserObjectClass(),
                  certdn,
                  email,
                  true,
                  true,
                  password,
                  extendedinformation);
        }

        try {
          attribute = getUserCertAttribute();
          LDAPAttribute certAttr =
              new LDAPAttribute(getUserCertAttribute(), incert.getEncoded());
          if (oldEntry != null) {
            String oldDn = oldEntry.getDN();
            if (getAddMultipleCertificates()) {
              modSet.add(new LDAPModification(LDAPModification.ADD, certAttr));
              if (LOG.isDebugEnabled()) {
                LOG.debug(
                    "Appended new certificate in user entry; "
                        + username
                        + ": "
                        + oldDn);
              }
            } else {
              modSet.add(
                  new LDAPModification(LDAPModification.REPLACE, certAttr));
              if (LOG.isDebugEnabled()) {
                LOG.debug(
                    "Replaced certificate in user entry; "
                        + username
                        + ": "
                        + oldDn);
              }
            }
          } else {
            attributeSet.add(certAttr);
            if (LOG.isDebugEnabled()) {
              LOG.debug(
                  "Added new certificate to user entry; "
                      + username
                      + ": "
                      + dn);
            }
          }
        } catch (CertificateEncodingException e) {
          String msg =
              INTRES.getLocalizedMessage(
                  "publisher.errorldapencodestore", "certificate");
          LOG.error(msg, e);
          throw new PublisherException(msg);
        }
      } else if (type == CertificateConstants.CERTTYPE_SUBCA
          || type == CertificateConstants.CERTTYPE_ROOTCA) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Publishing CA certificate to first available server of "
                  + getHostnames());
        }
        if (oldEntry != null) {
          modSet =
              getModificationSet(
                  oldEntry, certdn, null, false, false, password, incert);
        } else {
          objectclass = getCAObjectClass(); // just used for logging
          attributeSet =
              getAttributeSet(
                  incert,
                  getCAObjectClass(),
                  certdn,
                  null,
                  true,
                  false,
                  password,
                  extendedinformation);
        }
        try {
          attribute = getCACertAttribute();
          LDAPAttribute certAttr =
              new LDAPAttribute(getCACertAttribute(), incert.getEncoded());
          if (oldEntry != null) {
            modSet.add(
                new LDAPModification(LDAPModification.REPLACE, certAttr));
          } else {
            attributeSet.add(certAttr);
            // Also create using the crlattribute, it may be required
            LDAPAttribute crlAttr =
                new LDAPAttribute(getCRLAttribute(), getFakeCRL());
            attributeSet.add(crlAttr);
            // Also create using the arlattribute, it may be required
            LDAPAttribute arlAttr =
                new LDAPAttribute(getARLAttribute(), getFakeCRL());
            attributeSet.add(arlAttr);
            if (LOG.isDebugEnabled()) {
              LOG.debug("Added (fake) attribute for CRL and ARL.");
            }
          }
        } catch (CertificateEncodingException e) {
          String msg =
              INTRES.getLocalizedMessage(
                  "publisher.errorldapencodestore", "certificate");
          LOG.error(msg, e);
          throw new PublisherException(msg);
        }
      } else {
        String msg =
            INTRES.getLocalizedMessage(
                "publisher.notpubltype", Integer.valueOf(type));
        LOG.info(msg);
        throw new PublisherException(msg);
      }

      // PART 3: MODIFICATION AND ADDITION OF NEW USERS
      // Try all the listed servers
      Iterator<String> servers = getHostnameList().iterator();
      boolean connectionFailed;
      do {
        connectionFailed = false;
        String currentServer = servers.next();
        try {
          TCPTool.probeConnectionLDAP(
              currentServer,
              Integer.parseInt(getPort()),
              getConnectionTimeOut()); // Avoid waiting for halfdead-servers
          lc.connect(currentServer, Integer.parseInt(getPort()));
          // Execute a STARTTLS handshake if it was requested.
          if (getConnectionSecurity() == ConnectionSecurity.STARTTLS) {
            if (LOG.isDebugEnabled()) {
              LOG.debug("STARTTLS to LDAP server " + currentServer);
            }
            lc.startTLS();
          }
          // authenticate to the server
          lc.bind(
              ldapVersion,
              getLoginDN(),
              getLoginPassword().getBytes("UTF8"),
              ldapBindConstraints);
          // Add or modify the entry
          if (oldEntry != null && getModifyExistingUsers()) {
            LDAPModification[] mods = new LDAPModification[modSet.size()];
            mods = (LDAPModification[]) modSet.toArray(mods);
            String oldDn = oldEntry.getDN();
            if (LOG.isDebugEnabled()) {
              LOG.debug("Writing modification to DN: " + oldDn);
            }
            lc.modify(oldDn, mods, ldapStoreConstraints);
            String msg =
                INTRES.getLocalizedMessage(
                    "publisher.ldapmodify", "CERT", oldDn);
            LOG.info(msg);
          } else {
            if (this.getCreateNonExistingUsers()) {
              if (oldEntry == null) {
                // Check if the intermediate parent node is present, and if it
                // is not
                // we can create it, of allowed to do so by the publisher
                // configuration
                if (getCreateIntermediateNodes()) {
                  final String parentDN = CertTools.getParentDN(dn);
                  try {
                    lc.read(parentDN, ldapSearchConstraints);
                  } catch (LDAPException e) {
                    if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
                      this.createIntermediateNodes(lc, dn);
                      String msg =
                          INTRES.getLocalizedMessage(
                              "publisher.ldapaddedintermediate",
                              "CERT",
                              parentDN);
                      LOG.info(msg);
                    }
                  }
                }
                newEntry = new LDAPEntry(dn, attributeSet);
                if (LOG.isDebugEnabled()) {
                  LOG.debug("Adding DN: " + dn);
                }
                lc.add(newEntry, ldapStoreConstraints);
                String msg =
                    INTRES.getLocalizedMessage("publisher.ldapadd", "CERT", dn);
                LOG.info(msg);
              }
            }
          }
        } catch (LDAPException e) {
          connectionFailed = true;
          // If multiple certificates are allowed per entity, and the
          // certificate is already published,
          // an exception will be thrown. Catch this type of exception and just
          // log an informational message.
          if (e.getResultCode() == LDAPException.ATTRIBUTE_OR_VALUE_EXISTS) {
            final String msg =
                INTRES.getLocalizedMessage(
                    "publisher.certalreadyexists",
                    CertTools.getFingerprintAsString(incert),
                    dn,
                    e.getMessage());
            LOG.info(msg);
          } else if (servers.hasNext()) {
            LOG.warn(
                "Failed to publish to "
                    + currentServer
                    + ". Trying next in list.");
          } else {
            String msg =
                INTRES.getLocalizedMessage(
                    "publisher.errorldapstore",
                    "certificate",
                    attribute,
                    objectclass,
                    dn,
                    e.getMessage());
            LOG.error(msg, e);
            throw new PublisherException(msg);
          }
        } catch (UnsupportedEncodingException e) {
          String msg =
              INTRES.getLocalizedMessage(
                  "publisher.errorpassword", getLoginPassword());
          LOG.error(msg, e);
          throw new PublisherException(msg);
        } finally {
          // disconnect with the server
          try {
            lc.disconnect(ldapDisconnectConstraints);
          } catch (LDAPException e) {
            String msg =
                INTRES.getLocalizedMessage(
                    "publisher.errordisconnect", getLoginPassword());
            LOG.error(msg, e);
          }
        }
      } while (connectionFailed && servers.hasNext());
    } else {
      String msg =
          INTRES.getLocalizedMessage(
              "publisher.notpublwithstatus", Integer.valueOf(status));
      LOG.info(msg);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<storeCertificate()");
    }
    return true;
  }

  /**
   * Creates intermediate nodes to host an LDAP entry at <code>dn</code>.
   *
   * @param lc Active LDAP connection
   * @param dn Distinguished name
   * @throws PublisherException on fail
   */
  private void createIntermediateNodes(final LDAPConnection lc, final String dn)
      throws PublisherException {
    LDAPAttributeSet attrSet;
    LDAPEntry entry;
    for (String dnFragment : LdapTools.getIntermediateDNs(dn, getBaseDN())) {
      try {
        lc.read(dnFragment, ldapSearchConstraints);
      } catch (LDAPException e) {
        if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
          final String rdn = LdapTools.getFirstDNComponent(dnFragment);
          final String field = new String(rdn.substring(0, rdn.indexOf('=')));
          final String value = new String(rdn.substring(rdn.indexOf('=') + 1));

          attrSet = new LDAPAttributeSet();
          attrSet.add(getObjectClassAttribute(field));
          attrSet.add(new LDAPAttribute(field.toLowerCase(), value));
          entry = new LDAPEntry(dnFragment, attrSet);

          try {
            lc.add(entry, ldapStoreConstraints);
            if (LOG.isDebugEnabled()) {
              LOG.debug("Created node " + dnFragment);
            }
          } catch (LDAPException e1) {
            String msg =
                INTRES.getLocalizedMessage(
                    "publisher.ldapaddedintermediate", dnFragment);
            LOG.error(msg, e1);
            throw new PublisherException(msg);
          }
        }
      }
    }
  }

  /**
   * Returns an LDAPAttribute initialized with the LDAP object class definition
   * that corresponds to a DN <code>field</code>.
   *
   * <p>The only allowed fields are <code>O</code> (organization) and <code>OU
   * </code> (organizationalUnit).
   *
   * @param field A DN field (case-insensitive). Only <code>O</code> and <code>
   *     OU</code> are allowed.
   * @return LDAPAttribute initialized with the LDAP object class definition
   *     that corresponds to a DN <code>field</code>.
   */
  private LDAPAttribute getObjectClassAttribute(final String field) {
    final String lowCaseField = field.toLowerCase();
    if (lowCaseField.equals("o")) {
      return new LDAPAttribute(
          "objectclass", new String[] {"top", "organization"});
    } else if (lowCaseField.equals("ou")) {
      return new LDAPAttribute(
          "objectclass", new String[] {"top", "organizationalUnit"});
    } else {
      String msg =
          INTRES.getLocalizedMessage(
              "publisher.ldapintermediatenotappropriate", field);
      LOG.warn(msg);
      return new LDAPAttribute("objectclass");
    }
  }

  /**
   * @param admin token
   * @param incrl The DER coded CRL to be stored.
   * @param cafp Fingerprint (hex) of the CAs certificate.
   * @param number CRL number.
   * @param userDN if an DN object is not found in the certificate use object
   *     from user data instead, can be null.
   * @return true if storage was successful.
   * @throws PublisherException if a communication or other error occurs.
   *  @see org.ejbca.core.model.ca.publisher.BasePublisher#storeCRL */
  public boolean storeCRL(
      final AuthenticationToken admin,
      final byte[] incrl,
      final String cafp,
      final int number,
      final String userDN)
      throws PublisherException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">storeCRL");
    }
    int ldapVersion = LDAPConnection.LDAP_V3;

    final String dn;
    final String crldn;
    final boolean isDeltaCRL;
    try {
      // Extract the users DN from the crl. Use the least number of encodings...
      final X509CRL crl = CertTools.getCRLfromByteArray(incrl);
      crldn = CertTools.stringToBCDNString(crl.getIssuerDN().toString());
      // Is it a delta CRL?
      if (crl.getExtensionValue(Extension.deltaCRLIndicator.getId()) != null) {
        isDeltaCRL = true;
      } else {
        isDeltaCRL = false;
      }
      // Construct the DN used for the LDAP object entry
      dn = constructLDAPDN(crldn, userDN);
    } catch (Exception e) {
      String msg =
          INTRES.getLocalizedMessage("publisher.errorldapdecode", "CRL");
      LOG.error(msg, e);
      throw new PublisherException(msg);
    }

    LDAPConnection lc = createLdapConnection();

    // Check if the entry is already present, we will update it with the new
    // CRL.
    LDAPEntry oldEntry =
        searchOldEntity(null, ldapVersion, lc, crldn, userDN, null);

    LDAPEntry newEntry = null;
    ArrayList<LDAPModification> modSet = new ArrayList<LDAPModification>();
    LDAPAttributeSet attributeSet = null;

    if (oldEntry != null) {
      modSet =
          getModificationSet(oldEntry, crldn, null, false, false, null, null);
    } else {
      attributeSet =
          getAttributeSet(
              null,
              this.getCAObjectClass(),
              crldn,
              null,
              true,
              false,
              null,
              null);
    }

    if (isDeltaCRL) {
      // It's a delta CRL.
      LDAPAttribute attr = new LDAPAttribute(getDeltaCRLAttribute(), incrl);
      if (oldEntry != null) {
        modSet.add(new LDAPModification(LDAPModification.REPLACE, attr));
      } else {
        attributeSet.add(attr);
      }
    } else {
      // It's a CRL
      LDAPAttribute crlAttr = new LDAPAttribute(getCRLAttribute(), incrl);
      LDAPAttribute arlAttr = new LDAPAttribute(getARLAttribute(), incrl);
      if (oldEntry != null) {
        modSet.add(new LDAPModification(LDAPModification.REPLACE, crlAttr));
        modSet.add(new LDAPModification(LDAPModification.REPLACE, arlAttr));
      } else {
        attributeSet.add(crlAttr);
        attributeSet.add(arlAttr);
      }
    }
    if (oldEntry == null) {
      newEntry = new LDAPEntry(dn, attributeSet);
    }
    // Try all the listed servers
    Iterator<String> servers = getHostnameList().iterator();
    boolean connectionFailed;
    do {
      connectionFailed = false;
      String currentServer = servers.next();
      try {
        TCPTool.probeConnectionLDAP(
            currentServer,
            Integer.parseInt(getPort()),
            getConnectionTimeOut()); // Avoid waiting for halfdead-servers
        // connect to the server
        lc.connect(currentServer, Integer.parseInt(getPort()));
        // Execute a STARTTLS handshake if it was requested.
        if (getConnectionSecurity() == ConnectionSecurity.STARTTLS) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("STARTTLS to LDAP server " + currentServer);
          }
          lc.startTLS();
        }
        // authenticate to the server
        lc.bind(
            ldapVersion,
            getLoginDN(),
            getLoginPassword().getBytes("UTF8"),
            ldapBindConstraints);
        // Add or modify the entry
        if (oldEntry != null) {
          LDAPModification[] mods = new LDAPModification[modSet.size()];
          mods = (LDAPModification[]) modSet.toArray(mods);
          lc.modify(dn, mods, ldapStoreConstraints);
          String msg =
              INTRES.getLocalizedMessage("publisher.ldapmodify", "CRL", dn);
          LOG.info(msg);
        } else {
          lc.add(newEntry, ldapStoreConstraints);
          String msg =
              INTRES.getLocalizedMessage("publisher.ldapadd", "CRL", dn);
          LOG.info(msg);
        }
      } catch (LDAPException e) {
        connectionFailed = true;
        if (servers.hasNext()) {
          LOG.warn(
              "Failed to publish to "
                  + currentServer
                  + ". Trying next in list.");
        } else {
          String msg =
              INTRES.getLocalizedMessage(
                  "publisher.errorldapstore",
                  "CRL",
                  getCRLAttribute(),
                  getCAObjectClass(),
                  dn,
                  e.getMessage());
          LOG.error(msg, e);
          throw new PublisherException(msg);
        }
      } catch (UnsupportedEncodingException e) {
        String msg =
            INTRES.getLocalizedMessage(
                "publisher.errorpassword", getLoginPassword());
        LOG.error(msg, e);
        throw new PublisherException(msg);
      } finally {
        // disconnect with the server
        try {
          lc.disconnect(ldapDisconnectConstraints);
        } catch (LDAPException e) {
          String msg = INTRES.getLocalizedMessage("publisher.errordisconnect");
          LOG.error(msg, e);
        }
      }
    } while (connectionFailed && servers.hasNext());
    if (LOG.isTraceEnabled()) {
      LOG.trace("<storeCRL");
    }
    return true;
  }

  /**
   * Revokes a certificate, which means for LDAP that we may remove the
   * certificate or the whole user entry.
   *
   * @param admin Token
   * @param cert The certificate to be revoked.
   * @param username Username of end entity owning the certificate.
   * @param reason reason for revocation from RevokedCertInfo,
   *     RevokedCertInfo.NOT_REVOKED if not revoked.
   * @param userDN if an DN object is not found in the certificate use object
   *     from user data instead.
   * @throws PublisherException On fail
   */
  public void revokeCertificate(
      final AuthenticationToken admin,
      final Certificate cert,
      final String username,
      final int reason,
      final String userDN)
      throws PublisherException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">revokeCertificate()");
    }
    // Check first if we should do anything then revoking
    boolean removecert = getRemoveRevokedCertificates();
    boolean removeuser = getRemoveUsersWhenCertRevoked();
    if ((!removecert) && (!removeuser)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "The configuration for the publisher '"
                + getDescription()
                + "' does not allow removing of certificates or users.");
      }
      return;
    }
    if (removecert) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Removing user certificate from ldap");
      }
    }
    if (removeuser) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Removing user entry from ldap");
      }
    }

    int ldapVersion = LDAPConnection.LDAP_V3;
    LDAPConnection lc = createLdapConnection();

    final String dn;
    final String certdn;
    try {
      // Extract the users DN from the cert.
      certdn = CertTools.getSubjectDN(cert);
      dn = constructLDAPDN(certdn, userDN);
    } catch (Exception e) {
      String msg =
          INTRES.getLocalizedMessage(
              "publisher.errorldapdecode", "certificate");
      LOG.error(msg, e);
      throw new PublisherException(msg);
    }

    // Extract the users email from the cert.
    String email = CertTools.getEMailAddress(cert);

    // Check if the entry is already present, we will update it with the new
    // certificate.
    final LDAPEntry oldEntry;

    ArrayList<LDAPModification> modSet = null;

    if (!CertTools.isCA(cert)) {
      oldEntry =
          searchOldEntity(username, ldapVersion, lc, certdn, userDN, email);
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Removing end user certificate from first available server of "
                + getHostnames());
      }
      if (oldEntry != null) {
        if (removecert) {
          // Don't try to remove the cert if there does not exist any
          LDAPAttribute oldAttr = oldEntry.getAttribute(getUserCertAttribute());
          if (oldAttr != null) {
            modSet =
                getModificationSet(
                    oldEntry, certdn, null, false, true, null, cert);
            LDAPAttribute attr = new LDAPAttribute(getUserCertAttribute());
            modSet.add(new LDAPModification(LDAPModification.DELETE, attr));
          } else {
            String msg =
                INTRES.getLocalizedMessage("publisher.inforevokenocert");
            LOG.info(msg);
          }
        }
      } else {
        String msg = INTRES.getLocalizedMessage("publisher.errorrevokenoentry");
        LOG.warn(msg);
      }
    } else {
      oldEntry = null;
      // Removal of CA certificate isn't support because of object class
      // restrictions
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Not removing CA certificate from first available server of "
                + getHostnames()
                + ", because of object class restrictions.");
      }
    }

    // Try all the listed servers
    final Iterator<String> servers = getHostnameList().iterator();
    boolean isConnectionNotDone = true;
    if (LOG.isDebugEnabled() && (oldEntry == null)) {
      LOG.debug("Not modifying LDAP entry because there is no existing entry.");
    }
    while (oldEntry != null && isConnectionNotDone && servers.hasNext()) {
      isConnectionNotDone = false;
      String currentServer = servers.next();
      if (LOG.isDebugEnabled()) {
        LOG.debug("currentServer: " + currentServer);
      }
      try {
        TCPTool.probeConnectionLDAP(
            currentServer,
            Integer.parseInt(getPort()),
            getConnectionTimeOut()); // Avoid waiting for halfdead-servers
        lc.connect(currentServer, Integer.parseInt(getPort()));
        // Execute a STARTTLS handshake if it was requested.
        if (getConnectionSecurity() == ConnectionSecurity.STARTTLS) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("STARTTLS to LDAP server " + currentServer);
          }
          lc.startTLS();
        }
        // authenticate to the server
        lc.bind(
            ldapVersion,
            getLoginDN(),
            getLoginPassword().getBytes("UTF8"),
            ldapBindConstraints);
        // Add or modify the entry
        if (modSet != null && getModifyExistingUsers()) {
          if (removecert) {
            LDAPModification[] mods = new LDAPModification[modSet.size()];
            mods = (LDAPModification[]) modSet.toArray(mods);
            lc.modify(oldEntry.getDN(), mods, ldapStoreConstraints);
          }
          if (removeuser) {
            lc.delete(oldEntry.getDN(), ldapStoreConstraints);
          }
          String msg = INTRES.getLocalizedMessage("publisher.ldapremove", dn);
          LOG.info(msg);
        } else {
          if (LOG.isDebugEnabled()) {
            if (modSet == null) {
              LOG.debug(
                  "Not modifying LDAP entry because we don't have anything to"
                      + " modify.");
            }
            if (!getModifyExistingUsers()) {
              LOG.debug(
                  "Not modifying LDAP entry because we're not configured to do"
                      + " so.");
            }
          }
        }
      } catch (LDAPException e) {
        isConnectionNotDone = true;
        if (servers.hasNext()) {
          LOG.warn(
              "Failed to publish to "
                  + currentServer
                  + ". Trying next in list.");
        } else {
          String msg =
              INTRES.getLocalizedMessage("publisher.errorldapremove", dn);
          LOG.error(msg, e);
          throw new PublisherException(msg);
        }
      } catch (UnsupportedEncodingException e) {
        String msg =
            INTRES.getLocalizedMessage(
                "publisher.errorpassword", getLoginPassword());
        LOG.error(msg, e);
        throw new PublisherException(msg);
      } finally {
        // disconnect with the server
        try {
          lc.disconnect(ldapDisconnectConstraints);
        } catch (LDAPException e) {
          String msg = INTRES.getLocalizedMessage("publisher.errordisconnect");
          LOG.error(msg, e);
        }
      }
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<revokeCertificate()");
    }
  }

  /**
   * SearchOldEntity is the only method differing between regular ldap and ldap
   * search publishers. Apart from how they find existing users, the publishing
   * works the same.
   *
   * @param username Name
   * @param ldapVersion Version
   * @param lc LC
   * @param certDN Certificate DN
   * @param userDN User DN
   * @param email Email
   * @return LDAP entry
   * @throws PublisherException On fail
   */
  protected LDAPEntry searchOldEntity(
      final String username,
      final int ldapVersion,
      final LDAPConnection lc,
      final String certDN,
      final String userDN,
      final String email)
      throws PublisherException {
    LDAPEntry oldEntry = null; // return value
    // Try all the listed servers
    final Iterator<String> servers = getHostnameList().iterator();
    boolean connectionFailed;
    do {
      connectionFailed = false;
      final String currentServer = servers.next();
      if (LOG.isDebugEnabled()) {
        LOG.debug("Current server is: " + currentServer);
      }
      final String ldapdn = constructLDAPDN(certDN, userDN);
      try {
        TCPTool.probeConnectionLDAP(
            currentServer,
            Integer.parseInt(getPort()),
            getConnectionTimeOut()); // Avoid waiting for halfdead-servers
        // connect to the server
        lc.connect(currentServer, Integer.parseInt(getPort()));
        // Execute a STARTTLS handshake if it was requested.
        if (getConnectionSecurity() == ConnectionSecurity.STARTTLS) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("STARTTLS to LDAP server " + currentServer);
          }
          lc.startTLS();
        }
        // authenticate to the server
        lc.bind(
            ldapVersion,
            getLoginDN(),
            getLoginPassword().getBytes("UTF8"),
            ldapBindConstraints);
        // try to read the old object
        if (LOG.isDebugEnabled()) {
          LOG.debug("Searching for old entry with DN '" + ldapdn + "'");
        }
        oldEntry = lc.read(ldapdn, ldapSearchConstraints);
        if (LOG.isDebugEnabled()) {
          if (oldEntry != null) {
            LOG.debug("Found an old entry with DN '" + ldapdn + "'");
          } else {
            LOG.debug("Did not find an old entry with DN '" + ldapdn + "'");
          }
        }
      } catch (LDAPException e) {
        if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("No old entry exist for '" + ldapdn + "'.");
          }
        } else {
          connectionFailed = true;
          if (servers.hasNext()) {
            LOG.warn(
                "Failed to publish to "
                    + currentServer
                    + ". Trying next in list.");
          } else {
            String msg =
                INTRES.getLocalizedMessage(
                    "publisher.errorldapbind", e.getMessage());
            LOG.error(msg, e);
            throw new PublisherException(msg);
          }
        }
      } catch (UnsupportedEncodingException e) {
        String msg =
            INTRES.getLocalizedMessage(
                "publisher.errorpassword", getLoginPassword());
        throw new PublisherException(msg);
      } finally {
        // disconnect with the server
        try {
          lc.disconnect(ldapDisconnectConstraints);
        } catch (LDAPException e) {
          String msg = INTRES.getLocalizedMessage("publisher.errordisconnect");
          LOG.error(msg, e);
        }
      }
    } while (connectionFailed && servers.hasNext());
    return oldEntry;
  }

  /** @see org.ejbca.core.model.ca.publisher.BasePublisher#testConnection() */
  public void testConnection() throws PublisherConnectionException {
    int ldapVersion = LDAPConnection.LDAP_V3;
    LDAPConnection lc = createLdapConnection();
    // Try all the listed servers
    Iterator<String> servers = getHostnameList().iterator();
    boolean connectionFailed;
    do {
      connectionFailed = false;
      String currentServer = servers.next();
      LDAPEntry entry = null;
      try {
        TCPTool.probeConnectionLDAP(
            currentServer,
            Integer.parseInt(getPort()),
            getConnectionTimeOut()); // Avoid waiting for halfdead-servers
        // connect to the server
        lc.connect(currentServer, Integer.parseInt(getPort()));
        // Execute a STARTTLS handshake if it was requested.
        if (getConnectionSecurity() == ConnectionSecurity.STARTTLS) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("STARTTLS to LDAP server " + currentServer);
          }
          lc.startTLS();
        }
        // authenticate to the server
        lc.bind(
            ldapVersion,
            getLoginDN(),
            getLoginPassword().getBytes("UTF8"),
            ldapBindConstraints);
        // try to read the base object
        String baseDN = getBaseDN();
        if (LOG.isDebugEnabled()) {
          LOG.debug("Trying to read top node '" + baseDN + "'");
        }
        entry = lc.read(baseDN, ldapSearchConstraints);
        if (entry == null) {
          String msg = INTRES.getLocalizedMessage("publisher.errornobinddn");
          throw new PublisherConnectionException(msg);
        }
        if (LOG.isDebugEnabled()) {
          LOG.debug("Entry" + entry.toString());
        }
      } catch (LDAPException e) {
        connectionFailed = true;
        if (servers.hasNext()) {
          LOG.warn(
              "Failed to connect to "
                  + currentServer
                  + ". Trying next in list.",
              e);
        } else {
          String msg =
              INTRES.getLocalizedMessage(
                  "publisher.errorldapbind", e.getMessage());
          LOG.error(msg, e);
          throw new PublisherConnectionException(msg);
        }
      } catch (UnsupportedEncodingException e) {
        String msg =
            INTRES.getLocalizedMessage(
                "publisher.errorpassword", getLoginPassword());
        LOG.error(msg, e);
        throw new PublisherConnectionException(msg);
      } finally {
        // disconnect with the server
        try {
          lc.disconnect(ldapDisconnectConstraints);
        } catch (LDAPException e) {
          String msg = INTRES.getLocalizedMessage("publisher.errordisconnect");
          LOG.error(msg, e);
        }
      }
    } while (connectionFailed && servers.hasNext());
  }

  /**
   * @return connection
   */
  protected LDAPConnection createLdapConnection() {
    // Set timeouts
    int connectiontimeout = getConnectionTimeOut();
    ldapBindConstraints.setTimeLimit(connectiontimeout);
    ldapDisconnectConstraints.setTimeLimit(connectiontimeout);
    ldapConnectionConstraints.setTimeLimit(connectiontimeout);
    ldapSearchConstraints.setTimeLimit(getReadTimeOut());
    ldapStoreConstraints.setTimeLimit(getStoreTimeOut());
    if (LOG.isDebugEnabled()) {
      LOG.debug("connecttimeout: " + ldapConnectionConstraints.getTimeLimit());
      LOG.debug("bindtimeout: " + ldapBindConstraints.getTimeLimit());
      LOG.debug(
          "disconnecttimeout: " + ldapDisconnectConstraints.getTimeLimit());
      LOG.debug("readtimeout: " + ldapSearchConstraints.getTimeLimit());
      LOG.debug("storetimeout: " + ldapStoreConstraints.getTimeLimit());
      LOG.debug("connectionsecurity: " + getConnectionSecurity());
    }
    LDAPConnection lc;

    switch (getConnectionSecurity()) {
      case STARTTLS:
        lc = new LDAPConnection(new LDAPJSSEStartTLSFactory());
        break;
      case SSL:
        lc = new LDAPConnection(new LDAPJSSESecureSocketFactory());
        break;
      default:
        lc = new LDAPConnection();
    }

    lc.setConstraints(ldapConnectionConstraints);
    return lc;
  }

  /** @return the hostnames of ldap server. */
  public List<String> getHostnameList() {
    List<String> ret = new ArrayList<String>();
    String[] hostnames = getHostnames().split(";");
    for (int i = 0; i < hostnames.length; i++) {
      ret.add(hostnames[i]);
    }
    return ret;
  }

  /** @return the hostnames of ldap server. */
  public String getHostnames() {
    return (String) data.get(HOSTNAMES);
  }

  /** @param hostnames the hostname of ldap server. */
  public void setHostnames(final String hostnames) {
    data.put(HOSTNAMES, hostnames);
  }

  /**
   * @param connectionsecurity the type of security to use for LDAP connection.
   */
  public void setConnectionSecurity(
      final ConnectionSecurity connectionsecurity) {
    data.put(CONNECTIONSECURITY, connectionsecurity);
  }

  /** @return the type of security for the LDAP connection. */
  public ConnectionSecurity getConnectionSecurity() {
    Object o = data.get(CONNECTIONSECURITY);
    ConnectionSecurity ret = ConnectionSecurity.PLAIN;
    if (o == null) {
      // If o is null this might be an older (pre v12) version that
      // has not gotten upgraded correctly. In that case we see if there is a
      // setting for USESSL, if there is and it is set we return to use SSL.
      Object usessl = data.get(USESSL);
      if (usessl != null) {
        if (((Boolean) usessl).booleanValue()) {
          ret = ConnectionSecurity.SSL;
        }
      }
    } else {
      ret = (ConnectionSecurity) o;
    }
    return ret;
  }

  /** @return the port of ldap server. */
  public String getPort() {
    return (String) data.get(PORT);
  }

  /** @param port the port of ldap server. */
  public void setPort(final String port) {
    data.put(PORT, port);
  }

  /** @return the basedn of ldap server. */
  public String getBaseDN() {
    return (String) data.get(BASEDN);
  }

  /** @param basedn the basedn of ldap server. */
  public void setBaseDN(final String basedn) {
    data.put(BASEDN, basedn);
  }

  /** @return the logindn to the ldap server. */
  public String getLoginDN() {
    return (String) data.get(LOGINDN);
  }

  /** @param logindn the logindn to the ldap server. */
  public void setLoginDN(final String logindn) {
    data.put(LOGINDN, logindn);
  }

  /** @return the loginpwd to the ldap server. */
  public String getLoginPassword() {
    String pwd = (String) data.get(LOGINPASSWORD);
    // It may be obfuscated in the database, in that case de-obfuscate
    // "if" because older installations may not be obfuscated
    pwd = StringTools.deobfuscateIf(pwd);
    return pwd;
  }

  /** @param loginpwd the loginpwd to the ldap server. */
  public void setLoginPassword(final String loginpwd) {
    // Obfuscate password before we store it in the database
    final String pwd = StringTools.obfuscate(loginpwd);
    data.put(LOGINPASSWORD, pwd);
  }

  /** @return true if nonexisting users should be created */
  public boolean getCreateNonExistingUsers() {
    return ((Boolean) data.get(CREATENONEXISTING)).booleanValue();
  }

  /** @param createnonexistingusers if nonexisting users should be created. */
  public void setCreateNonExistingUsers(final boolean createnonexistingusers) {
    data.put(CREATENONEXISTING, Boolean.valueOf(createnonexistingusers));
  }

  /** @return true if existing users should be modified. */
  public boolean getModifyExistingUsers() {
    return ((Boolean) data.get(MODIFYEXISTING)).booleanValue();
  }

  /** @param modifyexistingusers if existing users should be modified. */
  public void setModifyExistingUsers(final boolean modifyexistingusers) {
    data.put(MODIFYEXISTING, Boolean.valueOf(modifyexistingusers));
  }

  /** @return true if existing user attributes should be modified. */
  public boolean getModifyExistingAttributes() {
    return ((Boolean) data.get(MODIFYEXISTINGATTR)).booleanValue();
  }

  /**
   * @param modifyexistingattributes if existing user attributes should be
   *     modified.
   */
  public void setModifyExistingAttributes(
      final boolean modifyexistingattributes) {
    data.put(MODIFYEXISTINGATTR, Boolean.valueOf(modifyexistingattributes));
  }

  /** @return true if existing user attributes should be added. */
  public boolean getAddNonExistingAttributes() {
    return ((Boolean) data.get(ADDNONEXISTINGATTR)).booleanValue();
  }

  /** @param modifyexistingusers if existing user attributes should be added. */
  public void setAddNonExistingAttributes(final boolean modifyexistingusers) {
    data.put(ADDNONEXISTINGATTR, Boolean.valueOf(modifyexistingusers));
  }

  /** @return the user object class in the ldap instance */
  public String getUserObjectClass() {
    return (String) data.get(USEROBJECTCLASS);
  }

  /** @param userobjectclass the user object class in the ldap instance */
  public void setUserObjectClass(final String userobjectclass) {
    data.put(USEROBJECTCLASS, userobjectclass);
  }

  /** @return the CA object class in the ldap instance */
  public String getCAObjectClass() {
    return (String) data.get(CAOBJECTCLASS);
  }

  /** @param caobjectclass the CA object class in the ldap instance */
  public void setCAObjectClass(final String caobjectclass) {
    data.put(CAOBJECTCLASS, caobjectclass);
  }

  /** @return the user cert attribute in the ldap instance */
  public String getUserCertAttribute() {
    return (String) data.get(USERCERTATTRIBUTE);
  }

  /** @param usercertattribute the user cert attribute in the ldap instance */
  public void setUserCertAttribute(final String usercertattribute) {
    data.put(USERCERTATTRIBUTE, usercertattribute);
  }

  /** @return the ca cert attribute in the ldap instance */
  public String getCACertAttribute() {
    return (String) data.get(CACERTATTRIBUTE);
  }

  /** @param cacertattribute the ca cert attribute in the ldap instance */
  public void setCACertAttribute(final String cacertattribute) {
    data.put(CACERTATTRIBUTE, cacertattribute);
  }

  /** @return the CRL attribute in the ldap instance */
  public String getCRLAttribute() {
    return (String) data.get(CRLATTRIBUTE);
  }

  /** @param crlattribute the CRL attribute in the ldap instance */
  public void setCRLAttribute(final String crlattribute) {
    data.put(CRLATTRIBUTE, crlattribute);
  }

  /** @return the delta CRL attribute in the ldap instance */
  public String getDeltaCRLAttribute() {
    if (data.get(DELTACRLATTRIBUTE) == null) {
      this.setDeltaCRLAttribute(DEFAULT_DELTACRLATTRIBUTE);
      return DEFAULT_DELTACRLATTRIBUTE;
    } else {
      return (String) data.get(DELTACRLATTRIBUTE);
    }
  }

  /** @param deltacrlattribute the delta CRL attribute in the ldap instance */
  public void setDeltaCRLAttribute(final String deltacrlattribute) {
    data.put(DELTACRLATTRIBUTE, deltacrlattribute);
  }

  /** @return the ARL attribute in the ldap instance */
  public String getARLAttribute() {
    return (String) data.get(ARLATTRIBUTE);
  }

  /** @param arlattribute the ARL attribute in the ldap instance */
  public void setARLAttribute(final String arlattribute) {
    data.put(ARLATTRIBUTE, arlattribute);
  }

  /**
   * Method getting a collection of DNFieldExtractor constants indicating which
   * fields of the x509 certificate DN that should be used in the LDAP DN.
   *
   * <p>Valid values are DNFieldExtractor.E, .UID, .CN, .SN, .GIVENNAME,
   * .SURNAME, .T, .OU, .L Other values should be defined in baseDN instead. If
   * there exists multiple fields of the same type, then will all fields be
   * mappen to LDAP dn.
   *
   * @return Collection of (Integer) containing DNFieldExtractor constants.
   */
  @SuppressWarnings("unchecked")
  public Collection<Integer> getUseFieldInLdapDN() {
    return (Collection<Integer>) data.get(USEFIELDINLDAPDN);
  }

  /**
   * Method setting a collection of DNFieldExtractor constants indicating which
   * fields of the x509 certificate DN that should be used in the LDAP DN.
   *
   * <p>Valid values are DNFieldExtractor.E, .UID, .CN, .SN, .GIVENNAME,
   * .SURNAME, .T, .OU, .L Other values should be defined in baseDN instead. If
   * there exists multiple fields of the same type, then will all fields be
   * mappen to LDAP dn.
   *
   * @param usefieldinldapdn values
   */
  public void setUseFieldInLdapDN(final Collection<Integer> usefieldinldapdn) {
    data.put(USEFIELDINLDAPDN, usefieldinldapdn);
  }

  /**
   * @return true if multiple certificates should be appended to existing user
   *     entries, instead of replacing.
   */
  public boolean getAddMultipleCertificates() {
    return ((Boolean) data.get(ADDMULTIPLECERTIFICATES)).booleanValue();
  }
  /**
   * @param appendcerts if multiple certificates should be appended to existing
   *     user entries, instead of replacing.
   */
  public void setAddMultipleCertificates(final boolean appendcerts) {
    data.put(ADDMULTIPLECERTIFICATES, Boolean.valueOf(appendcerts));
  }

  /**
   * @param removerevoked bool
   */
  public void setRemoveRevokedCertificates(final boolean removerevoked) {
    data.put(REMOVEREVOKED, Boolean.valueOf(removerevoked));
  }

  /**
   * @return bool
   */
  public boolean getRemoveRevokedCertificates() {
    boolean removerevoked = true; // -- default value
    if (data.get(REMOVEREVOKED) != null) {
      removerevoked = ((Boolean) data.get(REMOVEREVOKED)).booleanValue();
    }
    return removerevoked;
  }

  /**
   * @param removeuser bool
   */
  public void setRemoveUsersWhenCertRevoked(final boolean removeuser) {
    data.put(REMOVEUSERONCERTREVOKE, Boolean.valueOf(removeuser));
  }

  /**
   * @return bool
   */
  public boolean getRemoveUsersWhenCertRevoked() {
    boolean removeuser = false; // -- default value
    if (data.get(REMOVEUSERONCERTREVOKE) != null) {
      removeuser = ((Boolean) data.get(REMOVEUSERONCERTREVOKE)).booleanValue();
    }
    return removeuser;
  }

  /**
   * @param createnodes bool
   */
  public void setCreateIntermediateNodes(final boolean createnodes) {
    data.put(CREATEINTERMEDIATENODES, Boolean.valueOf(createnodes));
  }

  /**
   * @return Bool
   */
  public boolean getCreateIntermediateNodes() {
    boolean createnodes = false; // -- default value
    if (data.get(CREATEINTERMEDIATENODES) != null) {
      createnodes =
          ((Boolean) data.get(CREATEINTERMEDIATENODES)).booleanValue();
    }
    return createnodes;
  }

  /**
   * @param userpassword Bool
   */
  public void setUserPassword(final boolean userpassword) {
    data.put(SETUSERPASSWORD, Boolean.valueOf(userpassword));
  }

  /**
   * @return Bool
   */
  public boolean getSetUserPassword() {
    boolean userpassword = false; // -- default value
    if (data.get(SETUSERPASSWORD) != null) {
      userpassword = ((Boolean) data.get(SETUSERPASSWORD)).booleanValue();
    }
    return userpassword;
  }

  /** @return timout in milliseconds */
  public int getConnectionTimeOut() {
    int timeout = Integer.parseInt(DEFAULT_TIMEOUT);
    if (data.get(TIMEOUT) != null) {
      timeout = Integer.parseInt((String) data.get(TIMEOUT));
    }
    return timeout;
  }
  /** @return timout in milliseconds */
  public int getReadTimeOut() {
    int timeout = Integer.parseInt(DEFAULT_READTIMEOUT);
    if (data.get(READTIMEOUT) != null) {
      timeout = Integer.parseInt((String) data.get(READTIMEOUT));
    }
    return timeout;
  }
  /** @return timout in milliseconds */
  public int getStoreTimeOut() {
    int timeout = Integer.parseInt(DEFAULT_STORETIMEOUT);
    if (data.get(STORETIMEOUT) != null) {
      timeout = Integer.parseInt((String) data.get(STORETIMEOUT));
    }
    return timeout;
  }

  /** @param timeout timout in milliseconds */
  public void setConnectionTimeOut(final int timeout) {
    data.put(TIMEOUT, Integer.toString(timeout));
    ldapBindConstraints.setTimeLimit(timeout);
    ldapConnectionConstraints.setTimeLimit(timeout);
    ldapDisconnectConstraints.setTimeLimit(timeout);
  }
  /** @param timeout timout in milliseconds */
  public void setReadTimeOut(final int timeout) {
    data.put(READTIMEOUT, Integer.toString(timeout));
    ldapSearchConstraints.setTimeLimit(timeout);
  }
  /** @param timeout timout in milliseconds */
  public void setStoreTimeOut(final int timeout) {
    data.put(STORETIMEOUT, Integer.toString(timeout));
    ldapStoreConstraints.setTimeLimit(timeout);
  }

  // Private methods
  /**
   * Returns a list of attributes found in DN Can only be used when the same
   * attribute string is used in EJBCA and LDAP.
   *
   * @param dn The DN to search
   * @param attributes Strings to search for in the DN
   * @return An LDAPAttributeSet containing all attributes found int the DN
   */
  protected Collection<LDAPAttribute> getAttributesFromDN(
      final String dn, final String[] attributes) {
    Collection<LDAPAttribute> attributeList = new LinkedList<LDAPAttribute>();
    for (int i = 0; i < attributes.length; i++) {
      String attribute = CertTools.getPartFromDN(dn, attributes[i]);
      if (attribute != null) {
        attributeList.add(new LDAPAttribute(attributes[i], attribute));
      }
    }
    return attributeList;
  }

  /**
   * Returns a list containing LDAPModification's Can only be used when the same
   * attribute string is used in EJBCA and LDAP.
   *
   * @param dn The DN to search
   * @param oldEntry the old DN
   * @param attributes Strings to search for in the DN
   * @return An ArrayList containing LDAPModification for DN
   */
  protected ArrayList<LDAPModification> getModificationSetFromDN(
      final String dn, final LDAPEntry oldEntry, final String[] attributes) {
    ArrayList<LDAPModification> modset = new ArrayList<LDAPModification>();
    boolean modifyExisting = getModifyExistingAttributes();
    boolean addNonExisting = getAddNonExistingAttributes();
    for (int i = 0; i < attributes.length; i++) {
      String attribute = CertTools.getPartFromDN(dn, attributes[i]);
      LDAPAttribute oldattribute = oldEntry.getAttribute(attributes[i]);
      if (LOG.isDebugEnabled()) {
        if (oldattribute != null) {
          LOG.debug("removeme, oldattribute=" + oldattribute.toString());
        }
        if (dn != null) {
          LOG.debug("removeme, dn=" + dn);
        }
      }
      if (((attribute != null) && (oldattribute == null) && addNonExisting)
          || (((attribute != null) && (oldattribute != null))
              && modifyExisting)) {
        LDAPAttribute attr = new LDAPAttribute(attributes[i], attribute);
        modset.add(new LDAPModification(LDAPModification.REPLACE, attr));
      }
    }
    return modset;
  }

  /**
   * Creates an LDAPAttributeSet.
   *
   * @param cert the certificate to use or null if no cert involved.
   * @param objectclass the objectclass the attribute set should be of.
   * @param dn dn of the LDAP entry.
   * @param email email address for entry, or null
   * @param extra if we should add extra attributes except the objectclass to
   *     the attributeset.
   * @param person true if this is a person-entry, false if it is a CA.
   * @param password users password, to be added into SecurityObjects, and AD
   * @param extendedinformation for future use...
   * @return LDAPAtributeSet created...
   */
  protected LDAPAttributeSet getAttributeSet(
      final Certificate cert,
      final String objectclass,
      final String dn,
      final String email,
      final boolean extra,
      final boolean person,
      final String password,
      final ExtendedInformation extendedinformation) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getAttributeSet(dn=" + dn + ", email=" + email + ")");
    }
    LDAPAttributeSet attributeSet = new LDAPAttributeSet();
    LDAPAttribute attr = new LDAPAttribute("objectclass");
    // The full LDAP object tree is divided with ; in the objectclass
    StringTokenizer token = new StringTokenizer(objectclass, ";");
    while (token.hasMoreTokens()) {
      String value = token.nextToken();
      if (LOG.isDebugEnabled()) {
        LOG.debug("Adding objectclass value: " + value);
      }
      attr.addValue(value);
    }
    attributeSet.add(attr);

    /* To Add an entry to the directory,
     *   -- Create the attributes of the entry and add them to an attribute set
     *   -- Specify the DN of the entry to be created
     *   -- Create an LDAPEntry object with the DN and the attribute set
     *   -- Call the LDAPConnection add method to add it to the directory
     */
    if (extra) {
      attributeSet.addAll(getAttributesFromDN(dn, MATCHINGEXTRAATTRIBUTES));

      // Only persons have (normally) all these extra attributes.
      // A CA might have them if you don't use the default objectClass, but we
      // don't
      // handle that case.
      if (person) {
        // First get the easy ones where LDAP and EJBCA spelling is the same
        attributeSet.addAll(
            getAttributesFromDN(dn, MATCHINGPERSONALATTRIBUTES));
        // sn means surname in LDAP, and is required for persons
        String cn = CertTools.getPartFromDN(dn, "CN");
        String sn = CertTools.getPartFromDN(dn, "SURNAME");
        if ((sn == null) && (cn != null)) {
          // Only construct this if we are the standard object class
          if (objectclass.contains("inetOrgPerson")) {
            // Take surname to be the last part of the cn
            int index = cn.lastIndexOf(' ');
            if (index <= 0) {
              // If there is no natural sn, use cn since sn is required
              sn = cn;
            } else {
              if (index < cn.length()) {
                sn = new String(cn.substring(index + 1));
              }
            }
          }
        }
        if (sn != null) {
          attributeSet.add(new LDAPAttribute("sn", sn));
        }
        // gn means givenname in LDAP, and is required for persons
        String gn = CertTools.getPartFromDN(dn, "GIVENNAME");
        if ((gn == null) && (cn != null)) {
          // Only construct this if we are the standard object class
          if (objectclass.contains("inetOrgPerson")) {
            // Take givenname to be the first part of the cn
            int index = cn.indexOf(' ');
            if (index <= 0) {
              // If there is no natural gn/sn, ignore gn if we are using sn
              if (sn == null) {
                gn = cn;
              }
            } else {
              gn = new String(cn.substring(0, index));
            }
          }
        }
        if (gn != null) {
          attributeSet.add(new LDAPAttribute("givenName", gn));
        }
        String title = CertTools.getPartFromDN(dn, "T");
        if (title != null) {
          attributeSet.add(new LDAPAttribute("title", title));
        }
        if (email != null) {
          attributeSet.add(new LDAPAttribute("mail", email));
        }

        // If we have selected to use the SN (serialNUmber DN field, we will
        // also add it as an attribute
        // This is not present in the normal objectClass (inetOrgPerson)
        // Modifying the schema is as simple as adding serialNumber as MAY in
        // the inetOrgPerson object class in inetorgperson.schema.
        Collection<Integer> usefields = getUseFieldInLdapDN();
        if (usefields.contains(Integer.valueOf(DNFieldExtractor.SN))) {
          String serno = CertTools.getPartFromDN(dn, "SN");
          if (serno != null) {
            attributeSet.add(new LDAPAttribute("serialNumber", serno));
          }
        }
        // If we are using the custom schema inetOrgPersonWithCertSerno, we will
        // add the custom attribute certificateSerialNumber
        // This is, as the name implies, the X509V3 certificate serial number,
        // hex encoded into a printable string.
        if (objectclass.contains("inetOrgPersonWithCertSerno")
            && (cert != null)) {
          final String certSerno = CertTools.getSerialNumberAsString(cert);
          if (certSerno != null) {
            attributeSet.add(
                new LDAPAttribute("certificateSerialNumber", certSerno));
          }
        }

        // If this is an objectClass which is a SecurityObject, such as
        // simpleSecurityObject, we will add the password as well, if not null.
        if (getSetUserPassword() && (password != null)) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("Adding userPassword attribute");
          }
          attributeSet.add(new LDAPAttribute("userPassword", password));
        }
      }
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<getAttributeSet()");
    }
    return attributeSet;
  } // getAttributeSet

  /**
   * Creates an LDAPModificationSet.
   *
   * @param oldEntry the objectclass the attribute set should be of.
   * @param dn dn of the LDAP entry.
   * @param email email address for entry, or null
   * @param extra if we should add extra attributes except the objectclass to
   *     the modificationset.
   * @param person true if this is a person-entry, false if it is a CA.
   * @param password users password, to be added into SecurityObjects, and AD
   * @param cert the Certificate we are publishing, or null
   * @return List of LDAPModification created...
   */
  protected ArrayList<LDAPModification> getModificationSet(
      final LDAPEntry oldEntry,
      final String dn,
      final String email,
      final boolean extra,
      final boolean person,
      final String password,
      final Certificate cert) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getModificationSet(dn=" + dn + ", email=" + email + ")");
    }
    boolean modifyExisting = getModifyExistingAttributes();
    boolean addNonExisting = getAddNonExistingAttributes();
    final String objectclass = getUserObjectClass();
    ArrayList<LDAPModification> modSet = new ArrayList<LDAPModification>();
    // We get this, because we can not modify attributes that are present in the
    // original DN
    // i.e. if the ldap entry have a DN, we are not allowed to modify that
    if (extra) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Adding extra attributes to modificationSet");
      }
      modSet.addAll(
          getModificationSetFromDN(dn, oldEntry, MATCHINGEXTRAATTRIBUTES));
      // Only persons have (normally) all these extra attributes.
      // A CA might have them if you don't use the default objectClass, but we
      // don't
      // handle that case.
      if (person) {
        // sn means surname in LDAP, and is required for inetOrgPerson
        String cn = CertTools.getPartFromDN(dn, "CN");
        String sn = CertTools.getPartFromDN(dn, "SURNAME");
        if ((sn == null) && (cn != null)) {
          // Only construct this if we are the standard object class
          if (objectclass.contains("inetOrgPerson")) {
            // Take surname to be the last part of the cn
            int index = cn.lastIndexOf(' ');
            if (index <= 0) {
              // If there is no natural sn, use cn since sn is required
              sn = cn;
            } else {
              if (index < cn.length()) {
                sn = new String(cn.substring(index + 1));
              }
            }
          }
        }
        LDAPAttribute oldsn = oldEntry.getAttribute("sn");
        if (((sn != null) && (oldsn == null) && addNonExisting)
            || ((sn != null) && (oldsn != null) && modifyExisting)) {
          LDAPAttribute attr = new LDAPAttribute("sn", sn);
          modSet.add(new LDAPModification(LDAPModification.REPLACE, attr));
        }
        // gn means givenname in LDAP, and is required for inetOrgPerson
        String gn = CertTools.getPartFromDN(dn, "GIVENNAME");
        LDAPAttribute oldgn = oldEntry.getAttribute("GIVENNAME");
        if ((gn == null) && (cn != null)) {
          // Only construct this if we are the standard object class
          if (objectclass.contains("inetOrgPerson")) {
            // Take givenname to be the first part of the cn
            int index = cn.indexOf(' ');
            if (index <= 0) {
              // If there is no natural gn/sn, ignore gn if we are using sn
              if (sn == null) {
                gn = cn;
              }
            } else {
              gn = new String(cn.substring(0, index));
            }
          }
          if ((((gn != null) && (oldgn == null)) && addNonExisting)
              || (((gn != null) && (oldgn != null)) && modifyExisting)) {
            LDAPAttribute attr = new LDAPAttribute("givenName", gn);
            modSet.add(new LDAPModification(LDAPModification.REPLACE, attr));
          }
        }
        String title = CertTools.getPartFromDN(dn, "T");
        LDAPAttribute oldTitle = oldEntry.getAttribute("Title");
        if (((title != null) && (oldTitle == null) && addNonExisting)
            || ((title != null) && (oldTitle != null) && modifyExisting)) {
          LDAPAttribute attr = new LDAPAttribute("givenName", title);
          modSet.add(new LDAPModification(LDAPModification.REPLACE, attr));
        }
        LDAPAttribute oldEmail = oldEntry.getAttribute("mail");
        if (((email != null) && (oldEmail == null) && addNonExisting)
            || ((email != null) && (oldEmail != null) && modifyExisting)) {
          LDAPAttribute mailAttr = new LDAPAttribute("mail", email);
          modSet.add(new LDAPModification(LDAPModification.REPLACE, mailAttr));
        }

        // All generic personal attributes
        modSet.addAll(
            getModificationSetFromDN(dn, oldEntry, MATCHINGPERSONALATTRIBUTES));
        // If we have selected to use the SN (serialNUmber DN field, we will
        // also add it as an attribute
        // This is not present in the normal objectClass (inetOrgPerson)
        Collection<Integer> usefields = getUseFieldInLdapDN();
        if (usefields.contains(Integer.valueOf(DNFieldExtractor.SN))) {
          String serno = CertTools.getPartFromDN(dn, "SN");
          LDAPAttribute oldserno = oldEntry.getAttribute("SN");
          if (((serno != null) && (oldserno == null) && addNonExisting)
              || ((serno != null) && (oldserno != null) && modifyExisting)) {
            LDAPAttribute attr = new LDAPAttribute("serialNumber", serno);
            modSet.add(new LDAPModification(LDAPModification.REPLACE, attr));
          }
        }
        // If we are using the custom schema inetOrgPersonWithCertSerno, we will
        // add the custom attribute certificateSerialNumber
        // This is, as the name implies, the X509V3 certificate serial number,
        // hex encoded into a printable string.
        if (objectclass.contains("inetOrgPersonWithCertSerno")
            && (cert != null)) {
          final String certSerno = CertTools.getSerialNumberAsString(cert);
          if (certSerno != null) {
            LDAPAttribute attr =
                new LDAPAttribute("certificateSerialNumber", certSerno);
            modSet.add(new LDAPModification(LDAPModification.REPLACE, attr));
          }
        }

        // If this is an objectClass which is a SecurityObject, such as
        // simpleSecurityObject, we will add the password as well, if not null
        if ((getSetUserPassword() && (password != null))
            && (addNonExisting || modifyExisting)) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("Modifying userPassword attribute");
          }
          LDAPAttribute attr = new LDAPAttribute("userPassword", password);
          modSet.add(new LDAPModification(LDAPModification.REPLACE, attr));
        }
      }
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<getModificationSet()");
    }
    return modSet;
  } // getModificationSet

  /**
   * Constructs the LDAP DN for a certificate to be published. Only DN objects
   * defined by the publisher is used. For each DN object to be published: First
   * the certificate DN is search for this object. If no such certificate object
   * then the userdata DN is searched. If no such userdata object either the
   * object will not be a part of the LDAP DN.
   *
   * @param certDN certificate DN
   * @param userDataDN user data DN
   * @return LDAP DN to be used.
   */
  protected String constructLDAPDN(
      final String certDN, final String userDataDN) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "DN in certificate '"
              + certDN
              + "'. DN in user data '"
              + userDataDN
              + "'.");
    }
    final DNFieldExtractor certExtractor =
        new DNFieldExtractor(certDN, DNFieldExtractor.TYPE_SUBJECTDN);
    final DNFieldExtractor userDataExtractor =
        userDataDN != null
            ? new DNFieldExtractor(userDataDN, DNFieldExtractor.TYPE_SUBJECTDN)
            : null;

    Collection<Integer> usefields = getUseFieldInLdapDN();
    if (usefields instanceof List<?>) {
      Collections.sort((List<Integer>) usefields);
    }
    final X500NameBuilder nameBuilder =
        new X500NameBuilder(LdapNameStyle.INSTANCE);
    for (Integer fieldNum : usefields) { // There must be at least one
      String dnField = certExtractor.getFieldString(fieldNum);
      if (StringUtils.isEmpty(dnField) && userDataExtractor != null) {
        dnField = userDataExtractor.getFieldString(fieldNum);
      }

      if (StringUtils.isNotEmpty(dnField)) {
        RDN rdn = new X500Name(LdapNameStyle.INSTANCE, dnField).getRDNs()[0];
        nameBuilder.addRDN(rdn.getFirst());
      }
    }

    String retval = nameBuilder.build().toString() + "," + this.getBaseDN();
    if (LOG.isDebugEnabled()) {
      LOG.debug("LdapPublisher: constructed DN: " + retval);
    }
    return retval;
  }

  /** Dummy CRL. */
  protected static byte[] fakecrlbytes =
      Base64.decode(
          ("MIIBKDCBkgIBATANBgkqhkiG9w0BAQUFADAvMQ8wDQYDVQQDEwZUZXN0Q0ExDzAN"
           + "BgNVBAoTBkFuYVRvbTELMAkGA1UEBhMCU0UXDTA0MDExMjE0MTQyMloXDTA0MDEx"
           + "MzE0MTQyMlqgLzAtMB8GA1UdIwQYMBaAFK1tyidIzx1qpuj5OjHl/0Ro8xTDMAoG"
           + "A1UdFAQDAgEBMA0GCSqGSIb3DQEBBQUAA4GBABBSCWRAX8xyWQSuZYqR9MC8t4/V"
           + "Tp4xTGJeT1OPlCfuyeHyjUdvdjB/TjTgc4EOJ7eIF7aQU8Mp6AcUAKil/qBlrTYa"
           + "EFVr0WDeh2Aglgm4klAFnoJjDWfjTP1NVFdN4GMizqAz/vdXOY3DaDmkwx24eaRw"
           + "7SzqXca4gE7f1GTO")
              .getBytes());

  /**
   * Method to lazy create the fake CRL.
   *
   * @return fake CRL
   */
  protected byte[] getFakeCRL() {
    byte[] fakecrl = null;
    try {
      X509CRL crl = CertTools.getCRLfromByteArray(fakecrlbytes);
      fakecrl = crl.getEncoded();
    } catch (CRLException e) {
    }
    return fakecrl;
  }

  /** @return clone.
   * @see org.ejbca.core.model.ca.publisher.BasePublisher#clone() */
  @SuppressWarnings({"rawtypes", "unchecked"})
  public Object clone() throws CloneNotSupportedException {
    LdapPublisher clone = new LdapPublisher();
    HashMap clonedata = (HashMap) clone.saveData();

    Iterator i = (data.keySet()).iterator();
    while (i.hasNext()) {
      Object key = i.next();
      clonedata.put(key, data.get(key));
    }
    clone.loadData(clonedata);
    return clone;
  }

  /**
   * @return version
   * @see org.ejbca.core.model.ca.publisher.BasePublisher#getLatestVersion()
   */
  public float getLatestVersion() {
    return LATEST_VERSION;
  }

  /** Implemtation of UpgradableDataHashMap function upgrade. */
  public void upgrade() {
    LOG.trace(">upgrade");
    if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
      // New version of the class, upgrade
      String msg =
          INTRES.getLocalizedMessage(
              "publisher.upgrade", Float.valueOf(getVersion()));
      LOG.info(msg);
      if (data.get(ADDMULTIPLECERTIFICATES) == null) {
        setAddMultipleCertificates(false);
      }
      if (data.get(REMOVEREVOKED) == null) {
        setRemoveRevokedCertificates(true);
      }
      if (data.get(REMOVEUSERONCERTREVOKE) == null) {
        setRemoveUsersWhenCertRevoked(false);
      }
      if (data.get(CREATEINTERMEDIATENODES) == null) {
        setCreateIntermediateNodes(false); // v6
      }
      if (data.get(DELTACRLATTRIBUTE) == null) {
        setDeltaCRLAttribute(DEFAULT_DELTACRLATTRIBUTE); // v7
      }
      if (data.get(ADDNONEXISTINGATTR) == null) {
        setModifyExistingAttributes(false); // v8
        setAddNonExistingAttributes(true);
      }
      final int timeOutVersion = 9;
      if (getVersion() < timeOutVersion) {
        setConnectionTimeOut(getConnectionTimeOut()); // v9
      }
      if (data.get(SETUSERPASSWORD) == null) {
        setUserPassword(false); // v10
      }
      if (data.get(READTIMEOUT) == null) {
        setStoreTimeOut(getStoreTimeOut()); // v11
        setReadTimeOut(getReadTimeOut());
      }
      if (data.get(CONNECTIONSECURITY) == null) { // v12
        if (((Boolean) data.get(USESSL)).booleanValue()) {
          setConnectionSecurity(ConnectionSecurity.SSL);
        } else {
          setConnectionSecurity(ConnectionSecurity.PLAIN);
        }
      }

      data.put(VERSION, Float.valueOf(LATEST_VERSION));
    }
    LOG.trace("<upgrade");
  }

  @Override
  public boolean willPublishCertificate(
      final int status, final int revocationReason) {
    return true;
  }

  @Override
  public void validateDataSource(final String dataSource)
      throws PublisherException {
    // Method not applicable for this publisher type!
  }
}
