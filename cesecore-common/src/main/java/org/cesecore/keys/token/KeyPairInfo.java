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
package org.cesecore.keys.token;

import java.io.Serializable;

/**
 * Representation of a KeyPair in a CryptoToken. Does not contain the actual
 * keys.
 *
 * @version $Id: KeyPairInfo.java 24844 2016-12-06 15:18:05Z samuellb $
 */
public class KeyPairInfo implements Serializable, Comparable<KeyPairInfo> {

  private static final long serialVersionUID = 1L;

  /** ALias. */
  private String alias = "";
  /** Alg. */
  private String keyAlgorithm;
  /** Spec. */
  private String keySpecification;
  /** ID. */
  private String subjectKeyID = "";

  /**
   * @param anAlias Alias
   * @param aKeyAlgorithm Alg
   * @param aKeySpecification Spec
   * @param aSubjectKeyID ID
   */
  public KeyPairInfo(
      final String anAlias,
      final String aKeyAlgorithm,
      final String aKeySpecification,
      final String aSubjectKeyID) {
    this.alias = anAlias;
    this.keyAlgorithm = aKeyAlgorithm;
    this.keySpecification = aKeySpecification;
    this.subjectKeyID = aSubjectKeyID;
  }

  /**
   * @return alias
   */
  public String getAlias() {
    return alias;
  }

  /**
   * @param anAlias alias
   */
  public void setAlias(final String anAlias) {
    this.alias = anAlias;
  }

  /**
   * @return alg
   */
  public String getKeyAlgorithm() {
    return keyAlgorithm;
  }

  /**
   * @param aKeyAlgorithm alg
   */
  public void setKeyAlgorithm(final String aKeyAlgorithm) {
    this.keyAlgorithm = aKeyAlgorithm;
  }

  /**
   * @return spec
   */
  public String getKeySpecification() {
    return keySpecification;
  }

  /**
   * @param aKeySpecification spec
   */
  public void setKeySpecification(final String aKeySpecification) {
    this.keySpecification = aKeySpecification;
  }

  /**
   * @return ID
   */
  public String getSubjectKeyID() {
    return subjectKeyID;
  }

  /**
   * @param aSubjectKeyID ID
   */
  public void setSubjectKeyID(final String aSubjectKeyID) {
    this.subjectKeyID = aSubjectKeyID;
  }

  @Override
  public int compareTo(final KeyPairInfo o) {
    int c;

    c = alias.compareTo(o.alias);
    if (c != 0) {
      return c;
    }

    // There shouldn't be multiple aliases with the same name, but we compare
    // the other fields just to be sure.
    c = keyAlgorithm.compareTo(o.keyAlgorithm);
    if (c != 0) {
      return c;
    }
    c = keySpecification.compareTo(o.keySpecification);
    if (c != 0) {
      return c;
    }

    return 0;
  }
}
