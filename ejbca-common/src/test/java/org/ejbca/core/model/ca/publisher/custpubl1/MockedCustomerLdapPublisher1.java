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
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherException;

/**
 * Mocked version of the CustomerLdapPublisher1 used in the unit tests.
 *
 * @version Id
 */
public class MockedCustomerLdapPublisher1 extends CustomerLdapPublisher1 {

      /** Param. */
  private boolean doStoreCertificateCalled;
  /** Param. */
  private DoStoreCertificateParameters doStoreCertificateParameters;
  /** Param. */
  private PublisherException doStoreCertificateException;

  /** Param. */
  private boolean doStoreCRLCalled;
  /** Param. */
  private boolean doTestConnectionCalled;

  /** Param. */
  private StoreLogParameters storeLogParameters;
  /** Param. */
  private boolean storeLogCalled;
  /** Param. */
  private PublisherException storeLogException;
  /** Param. */
  private DoStoreCRLParameters doStoreCRLParameters;
  /** Param. */
  private PublisherException doStoreCRLException;
  /** Param. */
  private PublisherConnectionException doTestConnectionException;

  /** Param. */
  private SearchOldEntityParameters searchOldEntityParameters;
  /** Param. */
  private PublisherException searchOldEntityException;
  /** Param. */
  private LDAPEntry searchOldEntityReturn;

  // doStoreCertificate
  @Override
  protected boolean doStoreCertificate(
      final Certificate incert,
      final String username,
      final String password,
      final String userDN,
      final ExtendedInformation extendedinformation)
      throws PublisherException {
    doStoreCertificateCalled = true;
    doStoreCertificateParameters =
        new DoStoreCertificateParameters(
            incert, username, password, userDN, extendedinformation);

    if (doStoreCertificateException != null) {
      throw doStoreCertificateException;
    }

    return true;
  }

  /**
   * @param adoStoreCertificateException except
   */
  public void setDoStoreCertificateException(
      final PublisherException adoStoreCertificateException) {
    this.doStoreCertificateException = adoStoreCertificateException;
  }

  /**
   * @return params
   */
  public DoStoreCertificateParameters getDoStoreCertificateParameters() {
    return doStoreCertificateParameters;
  }

  /**
   * @return bool
   */
  public boolean isDoStoreCertificateCalled() {
    return doStoreCertificateCalled;
  }

  // storeLog
  @Override
  protected void storeLog(
      final String level,
      final boolean success,
      final String message,
      final Exception exception)
      throws PublisherException {
    storeLogParameters =
        new StoreLogParameters(level, success, message, exception);
    storeLogCalled = true;

    if (storeLogException != null) {
      throw storeLogException;
    }
  }

  /**
   * @return params
   */
  public StoreLogParameters getStoreLogParameters() {
    return storeLogParameters;
  }

  /**
   * @return bool
   */
  public boolean isStoreLogCalled() {
    return storeLogCalled;
  }

  /**
   * @param publisherException except
   */
  public void setStoreLogException(
      final PublisherException publisherException) {
    this.storeLogException = publisherException;
  }

  // doStoreCRL
  @Override
  protected void doStoreCRL(final byte[] incrl) throws PublisherException {
    doStoreCRLCalled = true;
    this.doStoreCRLParameters = new DoStoreCRLParameters(incrl);
    if (doStoreCRLException != null) {
      throw doStoreCRLException;
    }
  }

  /**
   * @return bool
   */
  public boolean isDoStoreCRLCalled() {
    return doStoreCRLCalled;
  }

  /**
   * @return params
   */
  public DoStoreCRLParameters getDoStoreCRLParameters() {
    return doStoreCRLParameters;
  }

  /**
   * @param publisherException except
   */
  public void setDoStoreCRLException(
      final PublisherException publisherException) {
    this.doStoreCRLException = publisherException;
  }

  // doTestConnection
  @Override
  protected void doTestConnection() throws PublisherConnectionException {
    this.doTestConnectionCalled = true;
    if (doTestConnectionException != null) {
      throw doTestConnectionException;
    }
  }

  /**
   * @param adoTestConnectionException except
   */
  public void setDoTestConnectionException(
      final PublisherConnectionException adoTestConnectionException) {
    this.doTestConnectionException = adoTestConnectionException;
  }

  /**
   * @return bool
   */
  public boolean isDoTestConnectionCalled() {
    return doTestConnectionCalled;
  }

  // searchOldEntity
  @Override
  protected LDAPEntry searchOldEntity(
      final LDAPConnection lc, final String ldapDN) throws PublisherException {
    this.searchOldEntityParameters = new SearchOldEntityParameters(lc, ldapDN);
    if (searchOldEntityException != null) {
      throw searchOldEntityException;
    }
    return searchOldEntityReturn;
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
   * @param asearchOldEntityReturn ldap
   */
  public void setSearchOldEntityReturn(final LDAPEntry asearchOldEntityReturn) {
    this.searchOldEntityReturn = asearchOldEntityReturn;
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
     * @param amessage message
     * @param anexception exception
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
     * @return level
     */
    public String getLevel() {
      return level;
    }

    /**
     * @return bool
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
     * @return exception
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
     * @param auserDN dn
     * @param theextendedinformation info
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
     * @return Cert
     */
    public Certificate getIncert() {
      return incert;
    }

    /**
     * @return User
     */
    public String getUsername() {
      return username;
    }

    /**
     * @return PWD
     */
    public String getPassword() {
      return password;
    }

    /**
     * @return DN
     */
    public String getUserDN() {
      return userDN;
    }

    /**
     * @return Info
     */
    public ExtendedInformation getExtendedinformation() {
      return extendedinformation;
    }
  }

  public static class DoStoreCRLParameters {
    /** Param. */
    private final byte[] incrl;

    /**
     * @param asincrl CRL
     */
    public DoStoreCRLParameters(final byte[] asincrl) {
      this.incrl = asincrl;
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
}
