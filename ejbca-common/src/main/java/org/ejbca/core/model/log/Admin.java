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

package org.ejbca.core.model.log;

import java.io.Serializable;
import java.security.cert.Certificate;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.authorization.AdminInformation;

/**
 * This is a class containing information about the administrator or admin
 * performing the event. Data contained in the class is preferably
 *
 * @author TomSelleck
 * @version $Id: Admin.java 22117 2015-10-29 10:53:42Z mikekushner $
 * @deprecated Use org.cesecore.authentication.tokens.AuthenticationToken
 *     instead.
 */
public class Admin implements Serializable {

  /**
   * Determines if a de-serialized file is compatible with this class.
   *
   * <p>Maintainers must change this value if and only if the new version of
   * this class is not compatible with old versions. See Sun docs for <a
   * href=http://java.sun.com/products/jdk/1.1/docs/guide
   * /serialization/spec/version.doc.html> details. </a>
   */
  private static final long serialVersionUID = -9221031402622809524L;

  /** Default CA Id for non-certificate administrators. */
  private static final int INTERNALCAID = 0;

  // Indicates the type of administrator.
  /** An administrator authenticated with client certificate. */
  private static final int TYPE_CLIENTCERT_USER = 0;
  /** A user of the public web pages.
  * Internal user in EJBCA, such as automatic job */
  private static final int TYPE_INTERNALUSER = 5;

  /** config. */
  public static final String[] ADMINTYPETEXTS = {
    "CLIENTCERT",
    "PUBLICWEBUSER",
    "RACMDLINE",
    "CACMDLINE",
    "BATCHCMDLINE",
    "INTERNALUSER"
  };

  // Special Users. (Constants cannot have 0 value).
  /** config. */
  private static final int SPECIALADMIN_PUBLICWEBUSER = 2000;
  /** config. */
  private static final int SPECIALADMIN_CACOMMANDLINEADMIN = 2001;
  /** config. */
  private static final int SPECIALADMIN_RAADMIN = 2002;
  /** config. */
  private static final int SPECIALADMIN_BATCHCOMMANDLINEADMIN = 2003;
  /** config. */
  private static final int SPECIALADMIN_INTERNALUSER = 2004;

  /** config. */
  private static final int[] ADMINTYPETOADMINENTITY = {
    0,
    Admin.SPECIALADMIN_PUBLICWEBUSER,
    Admin.SPECIALADMIN_RAADMIN,
    Admin.SPECIALADMIN_CACOMMANDLINEADMIN,
    Admin.SPECIALADMIN_BATCHCOMMANDLINEADMIN,
    Admin.SPECIALADMIN_INTERNALUSER
  };

  /** admin. */
  private static Admin internalAdmin = null;

  /** type. */
  protected int type = -1;
  /** data. */
  protected String data;
  /** cert. */
  protected Certificate certificate;
  /** user. */
  protected String username = null;
  /** email. */
  protected String email = null;

  /** transient authToken should _not_ be serialized. * */
  protected transient byte[] authToken = AdminInformation.getRandomToken();

  // We want to cache the AdminInformation, but we crete it on the fly after
  // deserialization..
  /** infi. */
  protected transient AdminInformation adminInformation = null;

  // Public Constructors
  /**
   * @param acertificate cert
   * @param ausername user
   * @param anemail email
   */
  public Admin(
      final Certificate acertificate,
      final String ausername,
      final String anemail) {
    this(
        TYPE_CLIENTCERT_USER,
        CertTools.getSerialNumberAsString(acertificate)
            + " : DN : \""
            + CertTools.getIssuerDN(acertificate)
            + "\"");
    this.certificate = acertificate;
    this.username = ausername;
    this.email = anemail;
  }

  /**
   * @param atype type
   * @param anipOrCertIssuerSerno ip address of
   *  publib web users etc or certserno
   *     and issuerDN for certificate authenticated admins (see other
   *     constructor above)
   */
  public Admin(final int atype, final String anipOrCertIssuerSerno) {
    this.type = atype;
    this.data = anipOrCertIssuerSerno;
  }

  /**
   * @param atype type
   */
  public Admin(final int atype) {
    this(atype, null);
  }

  // Public Methods

  /**
   * @return type
   */
  public int getAdminType() {
    return this.type;
  }

  /**
   * @return data
   */
  public String getAdminData() {
    return this.data;
  }

  /** Method that takes the internal data and returns a AdminInformation object
   * required by the Authorization module.
   *
   * @return info
   */
  public AdminInformation getAdminInformation() {
    if (adminInformation == null) {
      if (type == TYPE_CLIENTCERT_USER) {
        adminInformation = new AdminInformation(certificate, authToken);
      } else {
        adminInformation =
            new AdminInformation(ADMINTYPETOADMINENTITY[type], authToken);
      }
    }
    return adminInformation;
  }

  /**
   * Method that returns the caid of the CA, the admin belongs to. Doesn't work
   * properly for public web and special users so use with care.
   *
   * @return ID
   */
  public int getCaId() {
    int returnval = INTERNALCAID;
    if (type == TYPE_CLIENTCERT_USER) {
      returnval = CertTools.getIssuerDN(certificate).hashCode();
    }
    return returnval;
  }

  @Override
  public String toString() {
    String ret = "UNKNOWN";
    if ((type > -1) && (type < ADMINTYPETEXTS.length - 1)) {
      ret = ADMINTYPETEXTS[type];
    }
    return ret;
  }

  /** @return this administrator's email address or null if none is available */
  public String getEmail() {
    return email;
  }

  /** @return this administrator's username or null if none is available */
  public String getUsername() {
    return username;
  }

  /**
   * Manually sets the authToken. This should only be done in special cases such
   * as when restoring an Approval from the database. Note: Setting this to
   * AdminInformation.getRandomToken() means that this object is treated as it
   * were created internal in EJBCA. Do not do that unless trusting the object!
   *
   * @param anAuthToken Value of the authtoken.
   */
  public void setAuthToken(final byte[] anAuthToken) {
    this.authToken = anAuthToken;
  }

  /**
   * Instead of creating a new Admin(TYPE_INTERNALUSER), this can be used to use
   * a shared instance of the object.
   *
   * @return Admin
   */
  public static Admin getInternalAdmin() {
    if (internalAdmin == null) {
      internalAdmin = new Admin(TYPE_INTERNALUSER);
    }
    return internalAdmin;
  }
}
