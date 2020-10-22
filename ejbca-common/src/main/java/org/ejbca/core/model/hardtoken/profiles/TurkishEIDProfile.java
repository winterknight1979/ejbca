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
 * @version $Id: TurkishEIDProfile.java 22117 2015-10-29 10:53:42Z mikekushner $
 */
public class TurkishEIDProfile extends EIDProfile {

      /** Config. */

  public static final int[] AVAILABLEMINIMUMKEYLENGTHS = {1024, 2048};

  /** Config. */
  public static final int TYPE_TURKISHEID =
      HardTokenConstants.TOKENTYPE_TURKISHEID;
  /** Config. */

  public static final float LATEST_VERSION = 1;
  /** Config. */

  public static final int CERTUSAGE_SIGN = 0;
  /** Config. */
  public static final int CERTUSAGE_AUTHENC = 1;

  /** Config. */
  private static final long serialVersionUID = 5029374290818871258L;

  /** Config. */
  protected static final int NUMBEROFCERTIFICATES = 2;
  /** Config. */
  protected static final int NUMBEROFPINS = 1;

  /** Default Values. */
  public TurkishEIDProfile() {
    super();
    init();
  }

  private void init() {
    data.put(TYPE, Integer.valueOf(TYPE_TURKISHEID));

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

    ArrayList<Integer> pintypes = new ArrayList<Integer>(NUMBEROFPINS);
    pintypes.add(Integer.valueOf(PINTYPE_ASCII_NUMERIC));
    data.put(PINTYPE, pintypes);

    ArrayList<Integer> minpinlength = new ArrayList<Integer>(NUMBEROFPINS);
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
  /** length. */
  private static final int PIN_LENGTH = 4;

  /** @return lengths */
  public int[] getAvailableMinimumKeyLengths() {
    return AVAILABLEMINIMUMKEYLENGTHS;
  }

  /**
   * @param tokenidentificationstring id
   * @return bool
   * @deprecated deprecated
   * @see
   *     org.ejbca.core.model.hardtoken.profiles.HardTokenProfile#isTokenSupported(java.lang.String)
   */
  public boolean isTokenSupported(final String tokenidentificationstring) {
    return false;
  }

  /**
   * @return clone
   * @throws CloneNotSupportedException fail
   * @see org.ejbca.core.model.hardtoken.profiles.HardTokenProfile#clone()
   */
  public Object clone() throws CloneNotSupportedException {
    TurkishEIDProfile clone = new TurkishEIDProfile();
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

      data.put(VERSION, Float.valueOf(LATEST_VERSION));
    }
  }

  /** Override. */
  public void reInit() {
    init();
  }
}
