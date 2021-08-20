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

import java.io.Serializable;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringUtil;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.util.crypto.BCrypt;
import org.ejbca.util.crypto.CryptoTools;
import org.ejbca.util.crypto.SupportedPasswordHashAlgorithm;

/**
 * Representation of a User.
 *
 * <p>Passwords should me manipulated through helper functions setPassword() and
 * setOpenPassword(). The setPassword() function sets the hashed password, while
 * the setOpenPassword() method sets both the hashed password and the clear text
 * password. The method comparePassword() is used to verify a password against
 * the hashed password.
 *
 * @version $Id: UserData.java 27718 2018-01-03 08:31:26Z mikekushner $
 */
@Entity
@Table(name = "UserData")
public class UserData extends ProtectedData implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(UserData.class);
  /** Internal localization of logs and errors. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();

  /** PAram. */
  private String username;
  /** PAram. */
  private String subjectDN;
  /** PAram. */
  private int caId;
  /** PAram. */
  private String subjectAltName;
  /** PAram. */
  private String cardNumber;
  /** PAram. */
  private String subjectEmail;
  /** PAram. */
  private int status;
  /** PAram. */
  private int type;
  /** PAram. */
  private String clearPassword;
  /** PAram. */
  private String passwordHash;
  /** PAram. */
  private long timeCreated;
  /** PAram. */
  private long timeModified;
  /** PAram. */
  private int endEntityProfileId;
  /** PAram. */
  private int certificateProfileId;
  /** PAram. */
  private int tokenType;
  /** PAram. */
  private int hardTokenIssuerId;
  /** PAram. */
  private String extendedInformationData;
  /**
   * instantiated object of the above, used to not have to encode/decode the
   * object all the time. see PrePersist annotated method
   */
  private ExtendedInformation extendedInformation;

  /** PAram. */
  private String keyStorePassword;
  /** PAram. */
  private int rowVersion = 0;
  /** PAram. */
  private String rowProtection;
  // Performance optimization within a transaction, to not have to hash the
  // password when comparing internally in the same transaction, saving one
  // BCrypt operation
  /** PAram. */
  private transient String transientPwd;

  /**
   * Entity Bean holding info about a User. Create by sending in the instance,
   * username, password and subject DN. SubjectEmail, Status and Type are set to
   * default values (null, STATUS_NEW, USER_INVALID). and should be set using
   * the respective set-methods. Clear text password is not set at all and must
   * be set using setClearPassword();
   *
   * @param ausername the unique username used for authentication.
   * @param password the password used for authentication. If clearpwd is false
   *     this only sets passwordhash, if clearpwd is true it also sets cleartext
   *     password.
   * @param clearpwd true if clear password should be set for CA generated
   *     tokens (p12, jks, pem), false otherwise for only storing hashed
   *     passwords.
   * @param dn the DN the subject is given in his certificate.
   * @param caid ID
   * @param cardnumber the number printed on the card.
   * @param altname string of alternative names, i.e.
   *     rfc822name=foo2bar.com,dnsName=foo.bar.com, can be null
   * @param email user email address, can be null
   * @param atype user type, i.e. EndEntityTypes.USER_ENDUSER etc
   * @param eeprofileid end entity profile id, can be 0
   * @param certprofileid certificate profile id, can be 0
   * @param tokentype token type to issue to the user, i.e.
   *     SecConst.TOKEN_SOFT_BROWSERGEN
   * @param hardtokenissuerid hard token issuer id if hard token issuing is
   *     used, 0 otherwise
   * @param theextendedInformation ExtendedInformation object
   */
  public UserData(
      final String ausername,
      final String password,
      final boolean clearpwd,
      final String dn,
      final int caid,
      final String cardnumber,
      final String altname,
      final String email,
      final int atype,
      final int eeprofileid,
      final int certprofileid,
      final int tokentype,
      final int hardtokenissuerid,
      final ExtendedInformation theextendedInformation) {
    long time = new Date().getTime();
    setUsername(ausername);
    if (clearpwd) {
      setOpenPassword(password);
    } else {
      setPasswordHash(CryptoTools.makePasswordHash(password));
      setClearPassword(null);
    }
    transientPwd = password; // performance optimization within a transaction
    setSubjectDN(CertTools.stringToBCDNString(dn));
    setCaId(caid);
    setSubjectAltName(altname);
    setSubjectEmail(email);
    setStatus(EndEntityConstants.STATUS_NEW);
    setType(atype);
    setTimeCreated(time);
    setTimeModified(time);
    setEndEntityProfileId(eeprofileid);
    setCertificateProfileId(certprofileid);
    setTokenType(tokentype);
    setHardTokenIssuerId(hardtokenissuerid);
    setExtendedInformation(theextendedInformation);
    setCardNumber(cardnumber);
    if (LOG.isDebugEnabled()) {
      LOG.debug("Created user " + ausername);
    }
  }

  /** Empty. */
  public UserData() { }

  /**
   * @return user
   */
  // @Id @Column
  public String getUsername() {
    return username;
  }

  /**
   * @param ausername user
   */
  public void setUsername(final String ausername) {
    this.username = StringUtil.stripUsername(ausername);
  }

  /** @return the current Subject DN of the EE, never null */
  @Transient
  public String getSubjectDnNeverNull() {
    final String subjectDn = getSubjectDN();
    return subjectDn == null ? "" : subjectDn;
  }

  /**
   * Use getSubjectDnNeverNull() for consistent access, since Oracle will treat
   * empty Strings as NULL.
   *
   * @return value as it is stored in the database
   */
  // @Column(length=400)
  public String getSubjectDN() {
    return subjectDN;
  }

  /**
   * @param asubjectDN DN
   */
  public void setSubjectDN(final String asubjectDN) {
    this.subjectDN = asubjectDN;
  }

  /**
   * @return ID
   */
  // @Column
  public int getCaId() {
    return caId;
  }

  /**
   * @param acaId ID
   */
  public void setCaId(final int acaId) {
    this.caId = acaId;
  }

  /** @return the current Subject AN of the EE, never null */
  @Transient
  public String getSubjectAltNameNeverNull() {
    final String asubjectAltName = getSubjectAltName();
    return asubjectAltName == null ? "" : asubjectAltName;
  }

  /**
   * Use getSubjectAltNameNeverNull() for consistent access, since Oracle will
   * treat empty Strings as null.
   *
   * @return value as it is stored in the database
   */
  // @Column(length=2000)
  public String getSubjectAltName() {
    return subjectAltName;
  }

  /**
   * @param asubjectAltName name
   */
  public void setSubjectAltName(final String asubjectAltName) {
    this.subjectAltName = asubjectAltName;
  }

  /**
   * @return num
   */
  // @Column
  public String getCardNumber() {
    return cardNumber;
  }

  /**
   * @param acardNumber num
   */
  public void setCardNumber(final String acardNumber) {
    this.cardNumber = acardNumber;
  }

  /**
   * @return email
   */
  // @Column
  public String getSubjectEmail() {
    return subjectEmail;
  }

  /**
   * @param asubjectEmail email
   */
  public void setSubjectEmail(final String asubjectEmail) {
    this.subjectEmail = asubjectEmail;
  }

  /**
   * @return status
   */
  // @Column
  public int getStatus() {
    return this.status;
  }

  /**
   * @param astatus status
   */
  public void setStatus(final int astatus) {
    this.status = astatus;
  }

  /**
   * @return type
   */
  // @Column
  public int getType() {
    return type;
  }

  /**
   * @param atype type
   */
  public void setType(final int atype) {
    this.type = atype;
  }

  /**
   * This method is needed for Java Persistence. The preferred method for usage
   * is setOpenPassword(). Returns the clearPassword column as it is in the
   * database (may be obfuscated) or null.
   *
   * @return PWD
   */
  // @Column
  public String getClearPassword() {
    return clearPassword;
  }

  /**
   * This method is needed for Java Persistence. The preferred method for usage
   * is setOpenPassword(). Sets the clearPassword column in the database.
   *
   * @param aclearPassword PWD
   */
  public void setClearPassword(final String aclearPassword) {
    this.clearPassword = aclearPassword;
  }

  /**
   * Returns hashed password or null.
   *
   * @return Hash
   */
  // @Column
  public String getPasswordHash() {
    return passwordHash;
  }

  /**
   * Sets hash of password, this is the normal way to store passwords, but use
   * the method setPassword() instead.
   *
   * @param apasswordHash Hash
   */
  public void setPasswordHash(final String apasswordHash) {
    this.passwordHash = apasswordHash;
  }

  /**
   * Returns the time when the user was created.
   *
   * @return Time
   */
  // @Column
  public long getTimeCreated() {
    return timeCreated;
  }

  /**
   * Sets the time when the user was created.
   *
   * @param atimeCreated Time
   */
  public void setTimeCreated(final long atimeCreated) {
    this.timeCreated = atimeCreated;
  }

  /**
   * Returns the time when the user was last modified.
   *
   * @return Time
   */
  // @Column
  public long getTimeModified() {
    return timeModified;
  }

  /**
   * Sets the time when the user was last modified.
   *
   * @param atimeModified Time
   */
  public void setTimeModified(final long atimeModified) {
    this.timeModified = atimeModified;
  }

  /**
   * Returns the end entity profile id the user belongs to.
   *
   * @return Time
   */
  // @Column
  public int getEndEntityProfileId() {
    return endEntityProfileId;
  }

  /**
   * Sets the end entity profile id the user should belong to. 0 if profileid is
   * not applicable.
   *
   * @param anendEntityProfileId Time
   */
  public void setEndEntityProfileId(final int anendEntityProfileId) {
    this.endEntityProfileId = anendEntityProfileId;
  }

  /**
   * Returns the certificate profile id that should be generated for the user.
   *
   * @return Time
   */
  // @Column
  public int getCertificateProfileId() {
    return certificateProfileId;
  }

  /**
   * Sets the certificate profile id that should be generated for the user. 0 if
   * profileid is not applicable.
   *
   * @param acertificateProfileId time
   */
  public void setCertificateProfileId(final int acertificateProfileId) {
    this.certificateProfileId = acertificateProfileId;
  }

  /**
   * Returns the token type id that should be generated for the user.
   *
   * @return Time
   */
  // @Column
  public int getTokenType() {
    return tokenType;
  }

  /**
   * Sets the token type that should be generated for the user. Available token
   * types can be found in SecConst.
   *
   * @param atokenType Time
   */
  public void setTokenType(final int atokenType) {
    this.tokenType = atokenType;
  }

  /**
   * Returns the hard token issuer id that should genererate for the users hard
   * token.
   *
   * @return Time
   */
  // @Column
  public int getHardTokenIssuerId() {
    return hardTokenIssuerId;
  }

  /**
   * Sets the hard token issuer id that should genererate for the users hard
   * token. 0 if issuerid is not applicable.
   *
   * @param ahardTokenIssuerId ID
   */
  public void setHardTokenIssuerId(final int ahardTokenIssuerId) {
    this.hardTokenIssuerId = ahardTokenIssuerId;
  }

  /**
   * Non-searchable information about a user.
   *
   * @return Data
   */
  // @Column @Lob
  public String getExtendedInformationData() {
    return this.getZzzExtendedInformationData();
  }

  /**
   * Non-searchable information about a user.
   *
   * @param theextendedInformationData Data
   */
  public void setExtendedInformationData(
          final String theextendedInformationData) {
    this.setZzzExtendedInformationData(theextendedInformationData);
  }

  /**
   * Horrible work-around due to the fact that Oracle needs to have (LONG and)
   * CLOB values last in order to avoid ORA-24816.
   *
   * <p>Since Hibernate sorts columns by the property names, naming this
   * Z-something will apparently ensure that this column is used last.
   *
   * @return Data
   * @deprecated Use {@link #getExtendedInformationData()} instead
   */
  @Deprecated
  public String getZzzExtendedInformationData() {
    return extendedInformationData;
  }
  /**
   * @param zzzExtendedInformationData Data
   * @deprecated Use {@link #setExtendedInformationData(String)} instead
   */
  @Deprecated
  public void setZzzExtendedInformationData(
      final String zzzExtendedInformationData) {
    this.extendedInformationData = zzzExtendedInformationData;
  }

  /**
   * @return pwd
   */
  @Deprecated
  // Can't find any references to this field. Please un-deprecate if an use is
  // discovered! =)
  // @Column
  public String getKeyStorePassword() {
    return keyStorePassword;
  }

  /**
   * @param akeyStorePassword pwd
   */
  @Deprecated
  // Can't find any references to this field. Please un-deprecate if an use is
  // discovered! =)
  public void setKeyStorePassword(final String akeyStorePassword) {
    this.keyStorePassword = akeyStorePassword;
  }

  /**
   * @return version
   */
  // @Version @Column
  public int getRowVersion() {
    return rowVersion;
  }

  /**
   * @param arowVersion version
   */
  public void setRowVersion(final int arowVersion) {
    this.rowVersion = arowVersion;
  }

  // @Column @Lob
  @Override
  public String getRowProtection() {
    return this.getZzzRowProtection();
  }

  @Override
  public void setRowProtection(final String arowProtection) {
    this.setZzzRowProtection(arowProtection);
  }

  /**
   * Horrible work-around due to the fact that Oracle needs to have (LONG and)
   * CLOB values last in order to avoid ORA-24816.
   *
   * <p>Since Hibernate sorts columns by the property names, naming this
   * Z-something will apparently ensure that this column is used last.
   *
   * @return protect
   * @deprecated Use {@link #getRowProtection()} instead
   */
  @Deprecated
  public String getZzzRowProtection() {
    return rowProtection;
  }
  /**
   * @param zzzRowProtection protect
   * @deprecated Use {@link #setRowProtection(String)} instead
   */
  @Deprecated
  public void setZzzRowProtection(final String zzzRowProtection) {
    this.rowProtection = zzzRowProtection;
  }

  //
  // Public methods used to help us manage passwords
  //

  /**
   * Function that sets the BCDN representation of the string.
   *
   * @param dn DN
   */
  public void setDN(final String dn) {
    setSubjectDN(CertTools.stringToBCDNString(dn));
  }

  /**
   * Sets password in hashed form in the database, this way it cannot be read in
   * clear form.
   *
   * @param password Pass
   * @throws NoSuchAlgorithmException on fail
   */
  public void setPassword(final String password)
      throws NoSuchAlgorithmException {
    String apasswordHash = CryptoTools.makePasswordHash(password);
    setPasswordHash(apasswordHash);
    setClearPassword(null);
  }

  /**
   * Sets the password in both hashed and clear (obfuscated though) form in the
   * database, clear is needed for machine processing.
   *
   * @param password Pass
   */
  public void setOpenPassword(final String password) {
    String apasswordHash = CryptoTools.makePasswordHash(password);
    setPasswordHash(apasswordHash);
    setClearPassword(StringUtil.obfuscate(password));
  }

  /**
   * Returns clear text password (de-obfuscated) or null.
   *
   * @return Pass
   */
  @Transient
  public String getOpenPassword() {
    return StringUtil.deobfuscateIf(clearPassword);
  }

  /** @return which hashing algorithm was used for this UserData object */
  public SupportedPasswordHashAlgorithm findHashAlgorithm() {
    final String hash = getPasswordHash();
    if (StringUtils.startsWith(hash, "$2")) {
      return SupportedPasswordHashAlgorithm.SHA1_BCRYPT;
    } else {
      return SupportedPasswordHashAlgorithm.SHA1_OLD;
    }
  }

  /**
   * Verifies password by verifying against passwordhash.
   *
   * @param password Pass
   * @return bool
   * @throws NoSuchAlgorithmException Fail
   */
  public boolean comparePassword(final String password)
      throws NoSuchAlgorithmException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">comparePassword()");
    }
    boolean ret = false;
    if (password != null) {
      if (transientPwd != null) {
        // Performance optimization within a transaction, to not have to hash
        // the password when comparing internally in the same transaction,
        // saving one BCrypt operation
        ret = transientPwd.equals(password);
      } else {
        final String hash = getPasswordHash();
        // Check if it is a new or old style hashing
        switch (findHashAlgorithm()) {
          case SHA1_BCRYPT:
            // new style with good salt
            ret = BCrypt.checkpw(password, hash);
            break;
          case SHA1_OLD:
          default:
            ret =
                CryptoTools.makeOldPasswordHash(password)
                    .equals(getPasswordHash());
            break;
        }
      }
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<comparePassword()");
    }
    return ret;
  }

  //
  // Helper functions
  //

  @Override
  @Transient
  public UserData clone() {
    final UserData userData = new UserData();
    userData.caId = caId;
    userData.cardNumber = cardNumber;
    userData.certificateProfileId = certificateProfileId;
    userData.clearPassword = clearPassword;
    userData.endEntityProfileId = endEntityProfileId;
    userData.extendedInformationData = extendedInformationData;
    userData.hardTokenIssuerId = hardTokenIssuerId;
    userData.keyStorePassword = keyStorePassword;
    userData.passwordHash = passwordHash;
    userData.rowProtection = rowProtection;
    userData.rowVersion = rowVersion;
    userData.status = status;
    userData.subjectAltName = subjectAltName;
    userData.subjectDN = subjectDN;
    userData.subjectEmail = subjectEmail;
    userData.timeCreated = timeCreated;
    userData.timeModified = timeModified;
    userData.tokenType = tokenType;
    userData.type = type;
    userData.username = username;
    return userData;
  }

  /**
   * Non-searchable information about a user.
   *
   * @return Info
   */
  @Transient
  public ExtendedInformation getExtendedInformation() {
    if ((extendedInformation == null) && (extendedInformationData != null)) {
      extendedInformation = getExtendedInformationFromData();
    }
    return extendedInformation;
  }

  /**
   * Non-searchable information about a user.
   *
   * @param theextendedInformation Info
   */
  public void setExtendedInformation(
      final ExtendedInformation theextendedInformation) {
    this.extendedInformation = theextendedInformation;
    // If we are making it blank, make sure our data is blank as well, otherwise
    // getExtendedInformation
    // above will return the old value
    if (theextendedInformation == null) {
      extendedInformationData = null;
    }
  }
  /**
   * Non-searchable information about a user.
   *
   * @return Info
   */
  @Transient
  private ExtendedInformation getExtendedInformationFromData() {
    return EndEntityInformation.getExtendedInformationFromStringData(
        getExtendedInformationData());
  }

  /**
   * Non-searchable information about a user.
   *
   * @param theextendedInformation Info
   */
  public void setExtendedInformationPrePersist(
      final ExtendedInformation theextendedInformation) {
    setExtendedInformationData(
        EndEntityInformation.extendedInformationToStringData(
            theextendedInformation));
  }

  /**
   * Non-searchable information about a user.
   *
   * @return info
   */
  public EndEntityInformation toEndEntityInformation() {
    final EndEntityInformation data = new EndEntityInformation();
    data.setUsername(getUsername());
    data.setCAId(getCaId());
    data.setCertificateProfileId(getCertificateProfileId());
    data.setDN(getSubjectDnNeverNull());
    data.setEmail(getSubjectEmail());
    data.setEndEntityProfileId(getEndEntityProfileId());
    data.setExtendedInformation(getExtendedInformation());
    data.setHardTokenIssuerId(getHardTokenIssuerId());
    data.setPassword(getOpenPassword());
    data.setStatus(getStatus());
    data.setSubjectAltName(getSubjectAltNameNeverNull());
    data.setTimeCreated(new Date(getTimeCreated()));
    data.setTimeModified(new Date(getTimeModified()));
    data.setTokenType(getTokenType());
    data.setType(new EndEntityType(getType()));
    data.setCardNumber(getCardNumber());
    return data;
  }

  /**
   * Assumes authorization has already been checked.. Modifies the
   * ExtendedInformation object to reset the remaining login attempts.
   *
   * @param ei Info
   * @param username Iser
   * @return true if any change was made, false otherwise
   */
  @Transient
  public static boolean resetRemainingLoginAttemptsInternal(
      final ExtendedInformation ei, final String username) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">resetRemainingLoginAttemptsInternal");
    }
    final boolean ret;
    if (ei != null) {
      final int resetValue = ei.getMaxLoginAttempts();
      if (resetValue != -1 || ei.getRemainingLoginAttempts() != -1) {
        ei.setRemainingLoginAttempts(resetValue);
        final String msg =
            INTRES.getLocalizedMessage(
                "ra.resettedloginattemptscounter", username, resetValue);
        LOG.info(msg);
        ret = true;
      } else {
        ret = false;
      }
    } else {
      ret = false;
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<resetRamainingLoginAttemptsInternal: " + ret);
    }
    return ret;
  }

  //
  // Start Database integrity protection methods
  //

  @Transient
  @Override
  protected String getProtectString(final int version) {
    final ProtectionStringBuilder build = new ProtectionStringBuilder();
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build.append(getUsername());
    if (version >= 2) {
      // From version 2 we always use empty String here to allow future
      // migration between databases when this value is unset
      build.append(getSubjectDnNeverNull());
    } else {
      build.append(getSubjectDN());
    }
    build.append(getCardNumber()).append(getCaId());
    if (version >= 2) {
      // From version 2 we always use empty String here to allow future
      // migration between databases when this value is unset
      build.append(getSubjectAltNameNeverNull());
    } else {
      build.append(getSubjectAltName());
    }
    build.append(getCardNumber());
    build
        .append(getSubjectEmail())
        .append(getStatus())
        .append(getType())
        .append(getClearPassword())
        .append(getPasswordHash())
        .append(getTimeCreated())
        .append(getTimeModified());
    build
        .append(getEndEntityProfileId())
        .append(getCertificateProfileId())
        .append(getTokenType())
        .append(getHardTokenIssuerId())
        .append(getExtendedInformationData());
    return build.toString();
  }

  @Transient
  @Override
  protected int getProtectVersion() {
    return 2;
  }

  @PrePersist
  @PreUpdate
  @Override
  protected void protectData() {
    // This is a speed optimization to avoid encoding the extendedInformation
    // into XML data too often
    // We instead use the cached object in this class, and serialize it out to
    // XML data only when we persist the object
    // (create or update). This means you can call getExtendedInformation as
    // much as you want, without causing an expensive
    // XMLEncoder/Decoder
    setExtendedInformationPrePersist(getExtendedInformation());
    // After setting the data we want, continue on to the normal database
    // integrity protection
    super.protectData();
  }

  @PostLoad
  @Override
  protected void verifyData() {
    super.verifyData();
  }

  @Override
  @Transient
  protected String getRowId() {
    return getUsername();
  }

  //
  // End Database integrity protection methods
  //

}
