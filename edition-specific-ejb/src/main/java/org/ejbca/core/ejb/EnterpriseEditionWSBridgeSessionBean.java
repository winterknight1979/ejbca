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
package org.ejbca.core.ejb;

import java.util.List;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.util.KeyValuePair;

/**
 * JEE5 EJB lookup helper.
 *
 * @version $Id: EnterpriseEditionWSBridgeSessionBean.java 24602 2016-10-31
 *     13:26:34Z anatom $
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class EnterpriseEditionWSBridgeSessionBean
    implements EnterpriseEditionWSBridgeSessionLocal {

  @Override
  public void createCryptoToken(
      final AuthenticationToken admin,
      final String tokenName,
      final String tokenType,
      final String activationPin,
      final boolean autoActivate,
      final List<KeyValuePair> cryptoTokenProperties)
      throws UnsupportedMethodException {
    throw new UnsupportedMethodException(
        "This method can only be used in Enterprise edition.");
  }

  @Override
  public void generateCryptoTokenKeys(
      final AuthenticationToken admin,
      final String cryptoTokenName,
      final String keyPairAlias,
      final String keySpecification)
      throws UnsupportedMethodException {
    throw new UnsupportedMethodException(
        "This method can only be used in Enterprise edition.");
  }

  @Override
  public void createCA(
      final AuthenticationToken admin,
      final String caname,
      final String cadn,
      final String catype,
      final String encodedValidity,
      final String certprofile,
      final String signAlg,
      final int signedByCAId,
      final String cryptoTokenName,
      final List<KeyValuePair> purposeKeyMapping,
      final List<KeyValuePair> caProperties)
      throws UnsupportedMethodException {
    throw new UnsupportedMethodException(
        "This method can only be used in Enterprise edition.");
  }

  @Override
  public void addSubjectToRole(
      final AuthenticationToken admin,
      final String roleName,
      final String caName,
      final String matchWith,
      final String matchType,
      final String matchValue)
      throws UnsupportedMethodException {
    throw new UnsupportedMethodException(
        "This method can only be used in Enterprise edition.");
  }

  @Override
  public void removeSubjectFromRole(
      final AuthenticationToken admin,
      final String roleName,
      final String caName,
      final String matchWith,
      final String matchType,
      final String matchValue)
      throws UnsupportedMethodException {
    throw new UnsupportedMethodException(
        "This method can only be used in Enterprise edition.");
  }
}
