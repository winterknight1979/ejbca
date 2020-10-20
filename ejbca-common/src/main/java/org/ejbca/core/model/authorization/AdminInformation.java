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


package org.ejbca.core.model.authorization;

import java.io.Serializable;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Random;

/**
 * A class used to send user information to the authorization tree. It can
 * contain types of information, a X509Certificate or a special user type when
 * certificates cannot be retrieved. Special usertype constants is specified in
 * AdminEntity class.
 *
 * @version $Id: AdminInformation.java 22117 2015-10-29 10:53:42Z mikekushner $
 */
public class AdminInformation implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Special in JVM random token to authenticate specialuser.
   The token will work _if_ we are running within the same jvm as the service
    we call (i.e. EJBCA/JBoss server). */
  protected static final byte[] RANDOM_TOKEN = createRandomToken();

  // Public Methods
  /**
   * Creates a new instance of AdminInformation.
   *
   * @param aCertificate Cert
   * @param authToken Token
   */
  public AdminInformation(
      final Certificate aCertificate, final byte[] authToken) {
    this.certificate = aCertificate;
    this.specialuser = 0;
    this.localAuthToken = authToken;
  }


  /**
   * @param aspecialuser user
   * @param authToken token
   */
  public AdminInformation(final int aspecialuser, final byte[] authToken) {
    this.specialuser = aspecialuser;
    this.localAuthToken = authToken;
  }

  private AdminInformation(final byte[] authToken) {
    this.specialuser = 0;
    this.localAuthToken = authToken;
  }

  /**
   * @param roleId ID
   * @return Info
   */
  public static AdminInformation getAdminInformationByRoleId(final int roleId) {
    AdminInformation adminInformation = new AdminInformation(getRandomToken());
    adminInformation.adminGroupId = roleId;
    return adminInformation;
  }

  /**
   * @return Random
   */
  public static final byte[] createRandomToken() {
    final int size = 32;
    byte[] token = new byte[size];
    Random randomSource;
    randomSource = new SecureRandom();
    randomSource.nextBytes(token);
    return token;
  }

  /**
   * @return bool
   */
  public boolean isSpecialUser() {
    return this.specialuser != 0;
  }

  /**
   * @return bool
   */
  public boolean isGroupUser() {
    return this.adminGroupId != null;
  }

  /**
   * @return cert
   */
  public Certificate getX509Certificate() {
    return this.certificate;
  }

  /**
   * @return User
   */
  public int getSpecialUser() {
    return this.specialuser;
  }

  /**
   * @return ID
   */
  public int getGroupId() {
    return this.adminGroupId;
  }

  /**
   * @return token
   */
  public byte[] getLocalAuthToken() {
    return localAuthToken;
  }

  /**
   * @return token
   */
  public static final byte[] getRandomToken() {
    return RANDOM_TOKEN;
  }

  // Private fields
  /** Cert. */
  private Certificate certificate;
  /** User. */
  private int specialuser = 0;
  /** ID. */
  private Integer adminGroupId = null;

  /** transient as authToken should _not_ be serialized. * */
  private transient byte[] localAuthToken;
}
