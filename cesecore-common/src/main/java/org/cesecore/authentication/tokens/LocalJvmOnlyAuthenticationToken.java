/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.authentication.tokens;

import java.security.Principal;
import java.security.SecureRandom;
import java.util.Set;
import org.apache.commons.lang.ArrayUtils;
import org.apache.log4j.Logger;

/**
 * Common base class for tokens that are only valid in the JVM they are created
 * and could otherwise be spoofed. E.g. X509 client certificate validation
 * AuthenticationToken could otherwise be created and sent to a remote EJB
 * interface.
 *
 * @version $Id: LocalJvmOnlyAuthenticationToken.java 17625 2013-09-20 07:12:06Z
 *     netmackan $
 */
public abstract class LocalJvmOnlyAuthenticationToken
    extends AuthenticationToken {

  private static final long serialVersionUID = -6830176240864231535L;

  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(LocalJvmOnlyAuthenticationToken.class);

  /**
   * A random token that is unique to this JVM (e.g. the application server JVM
   * and a CLI JVM does not have the same token).
   */
  private static final byte[] RANDOM_TOKEN = createRandomToken();
  /** Size of token. */
  private static final int TOKEN_SIZE = 32;

  /** transient authToken should NOT be serialized. * */
  private transient byte[] authToken;

  /**
   * @param principals Principals
   * @param credentials Credentials
   * @see
   *     org.cesecore.authentication.tokens.AuthenticationToken#AuthenticationToken
   */
  protected LocalJvmOnlyAuthenticationToken(
      final Set<? extends Principal> principals, final Set<?> credentials) {
    super(principals, credentials);
    authToken = RANDOM_TOKEN;
  }

  /** @return true if this */
  protected final boolean isCreatedInThisJvm() {
    boolean isCreatedInThisJvm = ArrayUtils.isEquals(authToken, RANDOM_TOKEN);
    if (LOG.isTraceEnabled()) {
      LOG.trace("isCreatedInThisJvm: " + isCreatedInThisJvm);
    }
    return isCreatedInThisJvm;
  }

  /** Initialize rhe random token. */
  public void initRandomToken() {
    authToken = RANDOM_TOKEN;
  }

  /** @return a 32-byte random token. */
  private static byte[] createRandomToken() {
    final byte[] token = new byte[TOKEN_SIZE];
    new SecureRandom().nextBytes(token);
    return token;
  }
}
