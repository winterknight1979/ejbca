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

package org.ejbca.core.model.hardtoken.profiles;

import java.util.ArrayList;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.ejbca.core.model.hardtoken.HardTokenConstants;

/**
 * EnhancedEIDProfile with three certificates and key recovery functionallity.
 *
 * @version $Id: EnhancedEIDProfile.java 22117 2015-10-29 10:53:42Z mikekushner
 *     $
 */
public class EnhancedEIDProfile extends EIDProfile {

  // Public Constants

  private static final long serialVersionUID = 3655193301302470381L;

/** Config. */
  public static final int TYPE_ENHANCEDEID =
      HardTokenConstants.TOKENTYPE_ENHANCEDEID;

/** Config. */
  public static final float LATEST_VERSION = 4;

/** Config. */
  public static final int CERTUSAGE_SIGN = 0;
  /** Config. */
  public static final int CERTUSAGE_AUTH = 1;
  /** Config. */
  public static final int CERTUSAGE_ENC = 2;

/** Config. */
  public static final int PINTYPE_AUTH_SAME_AS_SIGN =
      SwedishEIDProfile.PINTYPE_AUTHENC_SAME_AS_SIGN;
  /** Config. */
  public static final int PINTYPE_ENC_SAME_AS_AUTH = 101;

  // Protected Constants
  /** Config. */
  protected static final int NUMBEROFCERTIFICATES = 3;

  // Private Constants
  /** Config. */
  public static final int[] AVAILABLEMINIMUMKEYLENGTHS = {1024, 1536, 2048};

  // Protected Fields
/** Config. */
  private final String[][] supportedTokens = {{"TODO"}};

  /** Default Values. */
  public EnhancedEIDProfile() {
    super();
    init();
  }

  /** Init. */
  private void init() {
    data.put(TYPE, Integer.valueOf(TYPE_ENHANCEDEID));

    ArrayList<Integer> certprofileids =
        new ArrayList<Integer>(NUMBEROFCERTIFICATES);
    certprofileids.add(
        Integer.valueOf(
            CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENSIGN));
    certprofileids.add(
        Integer.valueOf(
            CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENAUTH));
    certprofileids.add(
        Integer.valueOf(
            CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENENC));
    data.put(CERTIFICATEPROFILEID, certprofileids);

    ArrayList<Boolean> certWritable =
        new ArrayList<Boolean>(NUMBEROFCERTIFICATES);
    certWritable.add(Boolean.FALSE);
    certWritable.add(Boolean.FALSE);
    certWritable.add(Boolean.FALSE);
    data.put(CERTWRITABLE, certWritable);

    ArrayList<Integer> caids = new ArrayList<Integer>(NUMBEROFCERTIFICATES);
    caids.add(Integer.valueOf(CAID_USEUSERDEFINED));
    caids.add(Integer.valueOf(CAID_USEUSERDEFINED));
    caids.add(Integer.valueOf(CAID_USEUSERDEFINED));
    data.put(CAID, caids);

    ArrayList<Integer> pintypes = new ArrayList<Integer>(NUMBEROFCERTIFICATES);
    pintypes.add(Integer.valueOf(PINTYPE_ASCII_NUMERIC));
    pintypes.add(Integer.valueOf(PINTYPE_ASCII_NUMERIC));
    pintypes.add(Integer.valueOf(PINTYPE_ENC_SAME_AS_AUTH));
    data.put(PINTYPE, pintypes);

    ArrayList<Integer> minpinlength =
        new ArrayList<Integer>(NUMBEROFCERTIFICATES);
    minpinlength.add(Integer.valueOf(MIN_PIN_LENGTH));
    minpinlength.add(Integer.valueOf(MIN_PIN_LENGTH));
    minpinlength.add(Integer.valueOf(0));
    data.put(MINIMUMPINLENGTH, minpinlength);

    ArrayList<Boolean> iskeyrecoverable =
        new ArrayList<Boolean>(NUMBEROFCERTIFICATES);
    iskeyrecoverable.add(Boolean.FALSE);
    iskeyrecoverable.add(Boolean.FALSE);
    iskeyrecoverable.add(Boolean.TRUE);
    data.put(ISKEYRECOVERABLE, iskeyrecoverable);

    ArrayList<Boolean> reuseoldcertificate =
        new ArrayList<Boolean>(NUMBEROFCERTIFICATES);
    reuseoldcertificate.add(Boolean.FALSE);
    reuseoldcertificate.add(Boolean.FALSE);
    reuseoldcertificate.add(Boolean.FALSE);
    data.put(REUSEOLDCERTIFICATE, reuseoldcertificate);

    ArrayList<Integer> minimumkeylength =
        new ArrayList<Integer>(NUMBEROFCERTIFICATES);
    minimumkeylength.add(Integer.valueOf(MIN_KEY_LENGTH));
    minimumkeylength.add(Integer.valueOf(MIN_KEY_LENGTH));
    minimumkeylength.add(Integer.valueOf(MIN_KEY_LENGTH));
    data.put(MINIMUMKEYLENGTH, minimumkeylength);

    ArrayList<String> keytypes = new ArrayList<String>(NUMBEROFCERTIFICATES);
    keytypes.add(KEYTYPE_RSA);
    keytypes.add(KEYTYPE_RSA);
    keytypes.add(KEYTYPE_RSA);
    data.put(KEYTYPES, keytypes);
  }

  /** Min length. */
  private static final int MIN_KEY_LENGTH = 2048;

  /**
   * @return lengths
   */
  public int[] getAvailableMinimumKeyLengths() {
    return AVAILABLEMINIMUMKEYLENGTHS;
  }

  /**
   * @param tokenidentificationstring string
   * @return bool
   * @see
   *     org.ejbca.core.model.hardtoken.profiles.HardTokenProfile#isTokenSupported(java.lang.String)
   */
  public boolean isTokenSupported(final String tokenidentificationstring) {
    return this.isTokenSupported(supportedTokens, tokenidentificationstring);
  }

  /**
   * @return clone
   * @throws CloneNotSupportedException fail
   * @see
   *  org.ejbca.core.model.hardtoken.profiles.HardTokenProfile#clone()
   */
  public Object clone() throws CloneNotSupportedException {
    EnhancedEIDProfile clone = new EnhancedEIDProfile();

    super.clone(clone);

    return clone;
  }

  /**
   * @return version
   * @see
   *     org.ejbca.core.model.hardtoken.profiles.HardTokenProfile#getLatestVersion()
   */
  public float getLatestVersion() {
    return LATEST_VERSION;
  }

  /**
   * Upgrade.
   */
  public void upgrade() {
    if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
      // New version of the class, upgrade
      super.upgrade();

      if (data.get(MINIMUMPINLENGTH) == null) {
        ArrayList<Integer> minpinlength =
            new ArrayList<Integer>(NUMBEROFCERTIFICATES);
        minpinlength.add(Integer.valueOf(MIN_PIN_LENGTH));
        minpinlength.add(Integer.valueOf(MIN_PIN_LENGTH));
        minpinlength.add(Integer.valueOf(0));
        data.put(MINIMUMPINLENGTH, minpinlength);
      }

      if (data.get(REUSEOLDCERTIFICATE) == null) {
        ArrayList<Boolean> reuseoldcertificate =
            new ArrayList<Boolean>(NUMBEROFCERTIFICATES);
        reuseoldcertificate.add(Boolean.FALSE);
        reuseoldcertificate.add(Boolean.FALSE);
        reuseoldcertificate.add(Boolean.FALSE);
        data.put(REUSEOLDCERTIFICATE, reuseoldcertificate);
      }

      if (data.get(CERTWRITABLE) == null) {
        ArrayList<Boolean> certWritable =
            new ArrayList<Boolean>(NUMBEROFCERTIFICATES);
        certWritable.add(Boolean.FALSE);
        certWritable.add(Boolean.FALSE);
        certWritable.add(Boolean.FALSE);
        data.put(CERTWRITABLE, certWritable);
      }

      data.put(VERSION, Float.valueOf(LATEST_VERSION));
    }
  }

  /** Pin length. */
  private static final int MIN_PIN_LENGTH = 4;

  /** Override. */
  public void reInit() {
    init();
  }
}
