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
import java.util.Set;

/**
 * This class represents a Subject for the purpose of
 * authentication/authorization. javax.security.auth.Subject was not
 * implemented due to being overly coupled with the JAAS paradigm.
 * In order to avoid confusion with the
 * End Entity concept, the word 'user' is avoided in both contexts.
 *
 * TODO: Make proper hashcode/compare methods.
 *
 * @version $Id: AuthenticationSubject.java 18305 2013-12-16 13:59:56Z anatom $
 *
 */
public class AuthenticationSubject implements Serializable {

    private static final long serialVersionUID = 793575035911984396L;
    /** Principals. */
    protected final Set<Principal> principals;
    /** Credentials. */
    protected final Set<?> credentials;

    /**
     * Constructor.
     * @param thePrincipals principals
     * @param theCredentials Credentials
     */
    public AuthenticationSubject(
            final Set<Principal> thePrincipals, final Set<?> theCredentials) {
        this.principals = thePrincipals;
        this.credentials = theCredentials;
    }

    /** @return a {@link Set} of principals. */
    public Set<Principal> getPrincipals() {
        return principals;
    }


    /** @return a {@link Set} of Credentials. */
    public Set<?> getCredentials() {
        return credentials;
    }

}
