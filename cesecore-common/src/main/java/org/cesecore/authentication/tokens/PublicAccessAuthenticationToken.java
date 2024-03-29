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

import java.io.Serializable;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authorization.user.AccessUserAspect;

/**
 * AuthenticationToken representing a user that has provided no means of
 * authentication, e.g. a client accessing an interface like public RA web
 * pages.
 *
 * @version $Id: PublicAccessAuthenticationToken.java 26057 2017-06-22 08:08:34Z
 *     anatom $
 */
public class PublicAccessAuthenticationToken
    extends NestableAuthenticationToken {

      private static final long serialVersionUID = 1L;
      /** Metadata. */
      public static final PublicAccessAuthenticationTokenMetaData METADATA =
          new PublicAccessAuthenticationTokenMetaData();

      /** Principal. */
      private final PublicAccessPrincipal principal;
      /** Credential. */
      private final PublicAccessCredential credential;

  /**
   * Public access to the RA. Compare to PublicWebPrincipal which serves the
   * same purpose, but is used in the PublicWeb.
   */
  public static class PublicAccessPrincipal implements Principal, Serializable {
    private static final long serialVersionUID = 1L;
    /** Principal. */
    private final String principal;

    /**
     * Constrictor.
     *
     * @param aPrincipal principal
     */
    public PublicAccessPrincipal(final String aPrincipal) {
      this.principal = aPrincipal;
    }

    @Override
    public String getName() {
      return principal;
    }
  }

  private static class PublicAccessCredential implements Serializable {
    private static final long serialVersionUID = 1L;
    /** Should we encrypt. */
    private final boolean confidentialTransport;

    PublicAccessCredential(final boolean isConfidentialTransport) {
      this.confidentialTransport = isConfidentialTransport;
    }

    public boolean isConfidentialTransport() {
      return confidentialTransport;
    }
  }

  /**
   * Constructor.
   *
   * @param aPrincipal Proncipal.
   */
  @Deprecated
  public PublicAccessAuthenticationToken(final String aPrincipal) {
    this(aPrincipal, false);
  }

  /**
   * Constructor.
   *
   * @param aPrincipal Principal
   * @param confidentialTransport Transport
   */
  public PublicAccessAuthenticationToken(
      final String aPrincipal, final boolean confidentialTransport) {
    super(
        new HashSet<>(Arrays.asList(new PublicAccessPrincipal(aPrincipal))),
        new HashSet<>(
            Arrays.asList(new PublicAccessCredential(confidentialTransport))));
    this.principal = new PublicAccessPrincipal(aPrincipal);
    this.credential = new PublicAccessCredential(confidentialTransport);
  }

  @Override
  public boolean matches(final AccessUserAspect accessUser)
      throws AuthenticationFailedException {
    // Protect against spoofing by checking if this
    // token was created locally
    if (!super.isCreatedInThisJvm()) {
      return false;
    }
    if (!matchTokenType(accessUser.getTokenType())) {
      return false;
    }
    final PublicAccessMatchValue matchValue =
        (PublicAccessMatchValue)
            getMatchValueFromDatabaseValue(accessUser.getMatchWith());
    switch (matchValue) {
      case TRANSPORT_CONFIDENTIAL:
        return credential.isConfidentialTransport();
      case TRANSPORT_PLAIN:
        return !credential.isConfidentialTransport();
      case TRANSPORT_ANY:
        return true;
      default:
        return false;
    }
  }

  @Override
  public int getPreferredMatchKey() {
    return AuthenticationToken.NO_PREFERRED_MATCH_KEY;
    // not applicable to this type of authentication token
  }

  @Override
  public String getPreferredMatchValue() {
    return null;
  }

  /* Returns information of the entity this authentication token belongs to. *
  @Override
  public String toString() {
    return super.toString();
  } */

  /**
   * Override the default Principal.getName() when doing toString on this
   * object.
   */
  @Override
  protected String toStringOverride() {
    return principal.getName()
        + (credential.isConfidentialTransport()
            ? " (TRANSPORT_CONFIDENTIAL)"
            : " (TRANSPORT_PLAIN)");
  }

  @Override
  public int hashCode() {
    int hashCode =
        4711 * 1
            + ((principal.getName() == null)
                ? 0
                : principal.getName().hashCode());
    hashCode *= 17 + (credential.isConfidentialTransport() ? 0 : 1);
    return hashCode;
  }

  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    PublicAccessAuthenticationToken other =
        (PublicAccessAuthenticationToken) obj;
    if (principal.getName() == null) {
      if (other.principal.getName() != null) {
        return false;
      }
    } else if (!principal.getName().equals(other.principal.getName())) {
      return false;
    }
    return credential.isConfidentialTransport()
        == other.credential.isConfidentialTransport();
  }

  @Override
  protected String generateUniqueId() {
    return generateUniqueId(
            super.isCreatedInThisJvm(),
            principal.getName(),
            credential.isConfidentialTransport())
        + ";"
        + super.generateUniqueId();
  }

  @Override
  public AuthenticationTokenMetaData getMetaData() {
    return METADATA;
  }
}
