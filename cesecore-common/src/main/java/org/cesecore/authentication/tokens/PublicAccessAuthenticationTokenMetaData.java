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

import java.util.Arrays;

/**
 * Meta data definition and ServiceLoader marker for {@link org.cesecore.authentication.tokens.PublicAccessAuthenticationToken}.
 * 
 * @version $Id: PublicAccessAuthenticationTokenMetaData.java 25241 2017-02-10 02:10:43Z jeklund $
 */
public class PublicAccessAuthenticationTokenMetaData extends AuthenticationTokenMetaDataBase {

    public static final String TOKEN_TYPE = "PublicAccessAuthenticationToken";

    public PublicAccessAuthenticationTokenMetaData() {
        super(TOKEN_TYPE, Arrays.asList(PublicAccessMatchValue.values()), true);
    }
}
