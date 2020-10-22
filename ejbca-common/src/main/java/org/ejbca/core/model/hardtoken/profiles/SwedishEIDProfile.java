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
 * Hard token profile with a goal to fulfill Swedish EID standard.
 *
 * @version $Id: SwedishEIDProfile.java 22117 2015-10-29 10:53:42Z mikekushner $
 */
public class SwedishEIDProfile extends EIDProfile {

  private static final long serialVersionUID = -4972472165710748612L;

  // Public Constants
  /** Config. */
  public static final int TYPE_SWEDISHEID =
      HardTokenConstants.TOKENTYPE_SWEDISHEID;

  /** Config. */
  public static final float LATEST_VERSION = 4;

  /** Config. */
  public static final int CERTUSAGE_SIGN = 0;
  /** Config. */
  public static final int CERTUSAGE_AUTHENC = 1;

  /** Config. */
  public static final int PINTYPE_AUTHENC_SAME_AS_SIGN = 100;

  // Protected Constants
  /** Config. */
  protected static final int NUMBEROFCERTIFICATES = 2;

  // Private Constants
  /** Config. */
  public static final int[] AVAILABLEMINIMUMKEYLENGTHS = {1024, 2048};

  // Protected Fields

  /** Config. */
  private final String[][] supportedTokens = {{"TODO"}};

  /** Default Values. */
  public SwedishEIDProfile() {
    super();
    init();
  }

  private void init() {
    data.put(TYPE, Integer.valueOf(TYPE_SWEDISHEID));

    ArrayList<Integer> certprofileids =
        new ArrayList<Integer>(NUMBEROFCERTIFICATES);
    certprofileids.add(
        Integer.valueOf(
            CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENSIGN));
    certprofileids.add(
        Integer.valueOf(
            CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENAUTHENC));
    data.put(CERTIFICATEPROFILEID, certprofileids);

    ArrayList<Boolean> certWritable =
        new ArrayList<Boolean>(NUMBEROFCERTIFICATES);
    certWritable.add(Boolean.FALSE);
    certWritable.add(Boolean.FALSE);
    data.put(CERTWRITABLE, certWritable);

    ArrayList<Integer> caids = new ArrayList<Integer>(NUMBEROFCERTIFICATES);
    caids.add(Integer.valueOf(CAID_USEUSERDEFINED));
    caids.add(Integer.valueOf(CAID_USEUSERDEFINED));
    data.put(CAID, caids);

    ArrayList<Integer> pintypes = new ArrayList<Integer>(NUMBEROFCERTIFICATES);
    pintypes.add(Integer.valueOf(PINTYPE_ASCII_NUMERIC));
    pintypes.add(Integer.valueOf(PINTYPE_ASCII_NUMERIC));
    data.put(PINTYPE, pintypes);

    ArrayList<Integer> minpinlength =
        new ArrayList<Integer>(NUMBEROFCERTIFICATES);
    minpinlength.add(Integer.valueOf(PIN_LENGTH));
    minpinlength.add(Integer.valueOf(PIN_LENGTH));
    data.put(MINIMUMPINLENGTH, minpinlength);

    ArrayList<Boolean> iskeyrecoverable =
        new ArrayList<Boolean>(NUMBEROFCERTIFICATES);
    iskeyrecoverable.add(Boolean.FALSE);
    iskeyrecoverable.add(Boolean.FALSE);
    data.put(ISKEYRECOVERABLE, iskeyrecoverable);

    ArrayList<Boolean> reuseoldcertificate =
        new ArrayList<Boolean>(NUMBEROFCERTIFICATES);
    reuseoldcertificate.add(Boolean.FALSE);
    reuseoldcertificate.add(Boolean.FALSE);
    data.put(REUSEOLDCERTIFICATE, reuseoldcertificate);

    ArrayList<Integer> minimumkeylength =
        new ArrayList<Integer>(NUMBEROFCERTIFICATES);
    minimumkeylength.add(Integer.valueOf(KEY_LENGTH));
    minimumkeylength.add(Integer.valueOf(KEY_LENGTH));
    data.put(MINIMUMKEYLENGTH, minimumkeylength);

    ArrayList<String> keytypes = new ArrayList<String>(NUMBEROFCERTIFICATES);
    keytypes.add(KEYTYPE_RSA);
    keytypes.add(KEYTYPE_RSA);
    data.put(KEYTYPES, keytypes);
  }

  /** length. */
  private static final int KEY_LENGTH = 1024;

  /**
   * @return lengths
   */
  public int[] getAvailableMinimumKeyLengths() {
    return AVAILABLEMINIMUMKEYLENGTHS;
  }

  /**
   * @param tokenidentificationstring ID
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
   * @see org.ejbca.core.model.hardtoken.profiles.HardTokenProfile#clone() */
  public Object clone() throws CloneNotSupportedException {
    SwedishEIDProfile clone = new SwedishEIDProfile();
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

  /** Upgrade. */
  public void upgrade() {
    if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
      // New version of the class, upgrade
      super.upgrade();

      if (data.get(MINIMUMPINLENGTH) == null) {
        ArrayList<Integer> minpinlength =
            new ArrayList<Integer>(NUMBEROFCERTIFICATES);
        minpinlength.add(Integer.valueOf(PIN_LENGTH));
        minpinlength.add(Integer.valueOf(PIN_LENGTH));
        data.put(MINIMUMPINLENGTH, minpinlength);
      }

      if (data.get(REUSEOLDCERTIFICATE) == null) {
        ArrayList<Boolean> reuseoldcertificate =
            new ArrayList<Boolean>(NUMBEROFCERTIFICATES);
        reuseoldcertificate.add(Boolean.FALSE);
        reuseoldcertificate.add(Boolean.FALSE);
        data.put(REUSEOLDCERTIFICATE, reuseoldcertificate);
      }

      if (data.get(CERTWRITABLE) == null) {
        ArrayList<Boolean> certWritable =
            new ArrayList<Boolean>(NUMBEROFCERTIFICATES);
        certWritable.add(Boolean.FALSE);
        certWritable.add(Boolean.FALSE);
        data.put(CERTWRITABLE, certWritable);
      }

      data.put(VERSION, Float.valueOf(LATEST_VERSION));
    }
  }

  /** Length. */
  private static final int PIN_LENGTH = 4;

  /** Override. */
  public void reInit() {
    init();
  }
}
