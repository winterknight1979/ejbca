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
package org.ejbca.core.model.ca.publisher.custpubl1;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import java.security.cert.Certificate;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.core.model.ca.publisher.PublisherException;

/**
 * An additional mocked version of the CustomerLdapPublisher1 used by the unit
 * tests.
 *
 * @version Id
 */
public class SecondMockedCustomerLdapPublisher1 extends CustomerLdapPublisher1 {

      /** PAram. */
  private boolean searchOldEntityCalled;
  /** PAram. */
  private SearchOldEntityParameters searchOldEntityParameters;
  /** PAram. */
  private PublisherException searchOldEntityException;
  /** PAram. */
  private LDAPEntry searchOldEntityReturn;

  /** PAram. */
  private boolean writeCertEntryToLDAPCalled;
  /** PAram. */
  private WriteCertEntryToLDAPParameters writeCertEntryToLDAPParameters;
  /** PAram. */
  private PublisherException writeCertEntryToLDAPException;

  /** PAram. */
  private boolean writeCrlEntryToLDAPCalled;
  /** PAram. */
  private WriteCrlEntryToLDAPParameters writeCrlEntryToLDAPParameters;
  /** PAram. */
  private PublisherException writeCrlEntryToLDAPException;

  // searchOldEntity
  @Override
  protected LDAPEntry searchOldEntity(
      final LDAPConnection lc, final String ldapDN) throws PublisherException {
    this.searchOldEntityCalled = true;
    this.searchOldEntityParameters = new SearchOldEntityParameters(lc, ldapDN);
    if (searchOldEntityException != null) {
      throw searchOldEntityException;
    }
    return searchOldEntityReturn;
  }

  /**
   * @return bool
   */
  public boolean isSearchOldEntityCalled() {
    return searchOldEntityCalled;
  }

  /**
   * @return params
   */
  public SearchOldEntityParameters getSearchOldEntityParameters() {
    return searchOldEntityParameters;
  }

  /**
   * @param asearchOldEntityException except
   */
  public void setSearchOldEntityException(
      final PublisherException asearchOldEntityException) {
    this.searchOldEntityException = asearchOldEntityException;
  }

  /**
   * @param asearchOldEntityReturn entry
   */
  public void setSearchOldEntityReturn(final LDAPEntry asearchOldEntityReturn) {
    this.searchOldEntityReturn = asearchOldEntityReturn;
  }

  // writeCertEntryToLDAP
  @Override
  protected void writeCertEntryToLDAP(
      final LDAPConnection lc,
      final LDAPEntry oldEntry,
      final LDAPEntry newEntry,
      final String certFingerprint)
      throws PublisherException {
    this.writeCertEntryToLDAPCalled = true;
    this.writeCertEntryToLDAPParameters =
        new WriteCertEntryToLDAPParameters(
            lc, oldEntry, newEntry, certFingerprint);
    if (this.writeCertEntryToLDAPException != null) {
      throw writeCertEntryToLDAPException;
    }
  }

  /**
   * @return bool
   */
  public boolean isWriteCertEntryToLDAPCalled() {
    return writeCertEntryToLDAPCalled;
  }

  /**
   * @return params
   */
  public WriteCertEntryToLDAPParameters getWriteCertEntryToLDAPParameters() {
    return writeCertEntryToLDAPParameters;
  }


  /**
   * @param awriteCertEntryToLDAPException except
   */
  public void setWriteCertEntryToLDAPException(
      final PublisherException awriteCertEntryToLDAPException) {
    this.writeCertEntryToLDAPException = awriteCertEntryToLDAPException;
  }

  // writeCRLEntryToLDAP
  @Override
  protected void writeCrlEntryToLDAP(
      final LDAPConnection lc,
      final LDAPEntry oldEntry,
      final LDAPEntry newEntry)
      throws PublisherException {
    this.writeCrlEntryToLDAPCalled = true;
    this.writeCrlEntryToLDAPParameters =
        new WriteCrlEntryToLDAPParameters(lc, oldEntry, newEntry);
    if (this.writeCrlEntryToLDAPException != null) {
      throw writeCrlEntryToLDAPException;
    }
  }

  /**
   * @return bool
   */
  public boolean isWriteCrlEntryToLDAPCalled() {
    return writeCrlEntryToLDAPCalled;
  }

  /**
   * @return except
   */
  public WriteCrlEntryToLDAPParameters getWriteCrlEntryToLDAPParameters() {
    return writeCrlEntryToLDAPParameters;
  }

  /**
   * @param awriteCrlEntryToLDAPException except
   */
  public void setWriteCrlEntryToLDAPException(
      final PublisherException awriteCrlEntryToLDAPException) {
    this.writeCrlEntryToLDAPException = awriteCrlEntryToLDAPException;
  }

  public static class StoreLogParameters {
        /** Param. */
    private final String level;
    /** Param. */
    private final boolean success;
    /** Param. */
    private final String message;
    /** Param. */
    private final Exception exception;

    /**
     * @param alevel level
     * @param issuccess bool
     * @param amessage msh
     * @param anexception except
     */
    public StoreLogParameters(
        final String alevel,
        final boolean issuccess,
        final String amessage,
        final Exception anexception) {
      this.level = alevel;
      this.success = issuccess;
      this.message = amessage;
      this.exception = anexception;
    }

    /**
     * @return Level
     */
    public String getLevel() {
      return level;
    }

    /**
     * @return Success
     */
    public boolean isSuccess() {
      return success;
    }

    /**
     * @return message
     */
    public String getMessage() {
      return message;
    }

    /**
     * @return except
     */
    public Exception getException() {
      return exception;
    }
  }

  public static class DoStoreCertificateParameters {
        /** Param. */
    private final Certificate incert;
    /** Param. */
    private final String username;
    /** Param. */
    private final String password;
    /** Param. */
    private final String userDN;
    /** Param. */
    private final ExtendedInformation extendedinformation;

    /**
     * @param anincert cert
     * @param ausername user
     * @param apassword pwd
     * @param auserDN DN
     * @param theextendedinformation Info
     */
    public DoStoreCertificateParameters(
        final Certificate anincert,
        final String ausername,
        final String apassword,
        final String auserDN,
        final ExtendedInformation theextendedinformation) {
      this.incert = anincert;
      this.username = ausername;
      this.password = apassword;
      this.userDN = auserDN;
      this.extendedinformation = theextendedinformation;
    }

    /**
     * @return cert
     */
    public Certificate getIncert() {
      return incert;
    }

    /**
     * @return user
     */
    public String getUsername() {
      return username;
    }

    /**
     * @return pwd
     */
    public String getPassword() {
      return password;
    }

    /**
     * @return dn
     */
    public String getUserDN() {
      return userDN;
    }

    /**
     * @return info
     */
    public ExtendedInformation getExtendedinformation() {
      return extendedinformation;
    }
  }

  public static class DoStoreCRLParameters {
        /** Param. */
    private final byte[] incrl;

    /**
     * @param anincrl CRL
     */
    public DoStoreCRLParameters(final byte[] anincrl) {
      this.incrl = anincrl;
    }

    /**
     * @return CRL
     */
    public byte[] getIncrl() {
      return incrl;
    }
  }

  public static class SearchOldEntityParameters {
        /** Param. */
    private final LDAPConnection lc;
    /** Param. */
    private final String ldapDN;

    /**
     * @param anlc LC
     * @param anldapDN DN
     */
    public SearchOldEntityParameters(
        final LDAPConnection anlc, final String anldapDN) {
      this.lc = anlc;
      this.ldapDN = anldapDN;
    }

    /**
     * @return LC
     */
    public LDAPConnection getLc() {
      return lc;
    }

    /**
     * @return DN
     */
    public String getLdapDN() {
      return ldapDN;
    }
  }

  public static class WriteCertEntryToLDAPParameters {
        /** Param. */
    private final LDAPConnection lc;
    /** Param. */
    private final LDAPEntry oldEntry;
    /** Param. */
    private final LDAPEntry newEntry;
    /** Param. */
    private final String certFingerprint;

    /**
     * @param anlc LC
     * @param anoldEntry Old
     * @param anewEntry New
     * @param acertFingerprint FP
     */
    public WriteCertEntryToLDAPParameters(
        final LDAPConnection anlc,
        final LDAPEntry anoldEntry,
        final LDAPEntry anewEntry,
        final String acertFingerprint) {
      this.lc = anlc;
      this.oldEntry = anoldEntry;
      this.newEntry = anewEntry;
      this.certFingerprint = acertFingerprint;
    }

    /**
     * @return lc
     */
    public LDAPConnection getLc() {
      return lc;
    }

    /**
     * @return old
     */
    public LDAPEntry getOldEntry() {
      return oldEntry;
    }

    /**
     * @return new
     */
    public LDAPEntry getNewEntry() {
      return newEntry;
    }

    /**
     * @return fp
     */
    public String getCertFingerprint() {
      return certFingerprint;
    }
  }

  public static class WriteCrlEntryToLDAPParameters {
        /** Param. */
    private final LDAPConnection lc;
    /** Param. */
    private final LDAPEntry oldEntry;
    /** Param. */
    private final LDAPEntry newEntry;

    /**
     * @param anlc LC
     * @param anoldEntry Entry
     * @param anewEntry Entry
     */
    public WriteCrlEntryToLDAPParameters(
        final LDAPConnection anlc,
        final LDAPEntry anoldEntry,
        final LDAPEntry anewEntry) {
      this.lc = anlc;
      this.oldEntry = anoldEntry;
      this.newEntry = anewEntry;
    }

    /**
     * @return LC
     */
    public LDAPConnection getLc() {
      return lc;
    }

    /**
     * @return entry
     */
    public LDAPEntry getOldEntry() {
      return oldEntry;
    }

    /**
     * @return entry
     */
    public LDAPEntry getNewEntry() {
      return newEntry;
    }
  }
}
