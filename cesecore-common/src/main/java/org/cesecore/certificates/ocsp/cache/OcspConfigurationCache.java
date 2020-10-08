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
package org.cesecore.certificates.ocsp.cache;

import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.keybind.impl.OcspKeyBinding;

/**
 * This cache contains non persistent configuration elements that need to be
 * cached in order to be shared between all beans and servlets.
 *
 * @version $Id: OcspConfigurationCache.java 25867 2017-05-17 16:18:06Z
 *     mikekushner $
 */
public enum OcspConfigurationCache {
    /** Singleton instance. */
    INSTANCE;

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(OcspConfigurationCache.class);

  /** If true a certificate that does not exist in the database,
   *  but is issued by a CA the responder handles
   * will be treated as not revoked. Default is to treat is as "unknown".
   */
  private boolean nonExistingIsGood;
  /** If true a certificate that does not exist in the database,
   * but is issued by a CA the responder handles
   * will be treated as revoked. Default is to treat is as "unknown".
   */
  private boolean nonExistingIsRevoked;
  /** If true a certificate that does not exist
   *  in the database, but is issued by a CA the responder handles
   * be replied to with an unsigned "Unauthorized" reply.
   * Default is to treat is as "unknown".
   */
  private boolean nonExistingIsUnauthorized;

  /**
   * If this regex is fulfilled the "good" will be return
   * even if {@link #nonExistingIsGood} is false.
   */
  private Pattern nonExistingIsGoodOverideRegex;
  /**
   * If this regex is fulfilled the "unknown" will be return even
   * if {@link #nonExistingIsGood} or {@link #nonExistingIsRevoked} are true.
   */
  private Pattern nonExistingIsBadOverideRegex;
  /**
   * If this regex is fulfilled the "revoked" will be return
   * even if {@link #nonExistingIsRevoked} is false.
   */
  private Pattern nonExistingIsRevokedOverideRegex;

  /** Private constructor. */
  OcspConfigurationCache() {
    reloadConfiguration();
  }

  /** Reload config. */
  public void reloadConfiguration() {
    this.nonExistingIsGood = OcspConfiguration.getNonExistingIsGood();
    this.nonExistingIsRevoked = OcspConfiguration.getNonExistingIsRevoked();
    this.nonExistingIsUnauthorized =
        OcspConfiguration.getNonExistingIsUnauthorized();

    // Write an error to the logs if more than one of the above is true
    if ((this.nonExistingIsGood
            && (this.nonExistingIsRevoked || this.nonExistingIsUnauthorized))
        || (this.nonExistingIsRevoked && this.nonExistingIsUnauthorized)) {
      LOG.error(
          "Error: More than one of ocsp.nonexistingisgood,"
              + " ocsp.nonexistingisrevoked and ocsp.nonexistingisunauthorized"
              + " has been set to true at the same time.");
    }


      String value = OcspConfiguration.getNonExistingIsGoodOverideRegex();
      nonExistingIsGoodOverideRegex =
          value != null ? Pattern.compile(value) : null;


      value = OcspConfiguration.getNonExistingIsBadOverideRegex();
      nonExistingIsBadOverideRegex =
          value != null ? Pattern.compile(value) : null;


       value = OcspConfiguration.getNonExistingIsRevokedOverideRegex();
      nonExistingIsRevokedOverideRegex =
          value != null ? Pattern.compile(value) : null;

  }

  /**
   * @param ocspKeyBinding Binding
   * @return bool
   */
  public boolean isNonExistingUnauthorized(
          final OcspKeyBinding ocspKeyBinding) {
    // First we read the global default
    boolean lNonExistingIsUnauthorized = this.nonExistingIsUnauthorized;
    // If we have an OcspKeyBinding for this request we use it to override the
    // default
    if (ocspKeyBinding != null) {
      lNonExistingIsUnauthorized = ocspKeyBinding.getNonExistingUnauthorized();
    }
    return lNonExistingIsUnauthorized;
  }

  /**
   * @param url URL
   * @param ocspKeyBinding Binding
   * @return bool
   */
  public boolean isNonExistingGood(
      final StringBuffer url, final OcspKeyBinding ocspKeyBinding) {
    // First we read the global default
    boolean lNonExistingIsGood = this.nonExistingIsGood;
    // If we have an OcspKeyBinding for this request we use it to override the
    // default
    if (ocspKeyBinding != null) {
      lNonExistingIsGood = ocspKeyBinding.getNonExistingGood();
    }
    // Finally, if we have explicit configuration of the URL, this will
    // potentially override the value once again
    if (lNonExistingIsGood) {
      return !isRegexFulFilled(url, nonExistingIsBadOverideRegex);
    }
    return isRegexFulFilled(url, nonExistingIsGoodOverideRegex);
  }

  /**
   * @param url URL
   * @param ocspKeyBinding Binding
   * @return bool
   */
  public boolean isNonExistingRevoked(
      final StringBuffer url, final OcspKeyBinding ocspKeyBinding) {
    // First we read the global default
    boolean lNonExistingIsRevoked = this.nonExistingIsRevoked;
    // If we have an OcspKeyBinding for this request we use it to override the
    // default
    if (ocspKeyBinding != null) {
      lNonExistingIsRevoked = ocspKeyBinding.getNonExistingRevoked();
    }
    // Finally, if we have explicit configuration of the URL, this will
    // potentially override the value once again
    if (lNonExistingIsRevoked) {
      return !isRegexFulFilled(url, nonExistingIsBadOverideRegex);
    }
    return isRegexFulFilled(url, nonExistingIsRevokedOverideRegex);
  }

  private boolean isRegexFulFilled(
          final StringBuffer target, final Pattern pattern) {
    if (pattern == null || target == null) {
      return false;
    }
    return pattern.matcher(target.toString()).matches();
  }
}
