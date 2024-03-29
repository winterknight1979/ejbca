package org.cesecore.certificates.ca.extendedservices;

/**
 * @version $Id: ExtendedCAServiceTypes.java 21900 2015-09-17 19:22:21Z anatom $
 */
public final class ExtendedCAServiceTypeConstants {

    /** OCSP. */
  @Deprecated // Removed in EJBCA 6.0.0, and retained to support migration.
              // Remove once support for upgrading from 4.0.x is dropped.
  public static final int TYPE_OCSPEXTENDEDSERVICE = 1;
  // Number 2 was XKMS, do not re-use this as it might cause
  // interoperability/upgrade issues from older installations that had it
  /** CMS. */
  public static final int TYPE_CMSEXTENDEDSERVICE = 3;
  /** Token. */
  public static final int TYPE_HARDTOKENENCEXTENDEDSERVICE = 4;
  /** Recovery. */
  public static final int TYPE_KEYRECOVERYEXTENDEDSERVICE = 5;

  /** Not for instantiation. */
  private ExtendedCAServiceTypeConstants() { }
}
