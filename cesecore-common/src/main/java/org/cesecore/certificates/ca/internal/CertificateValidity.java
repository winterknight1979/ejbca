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
package org.cesecore.certificates.ca.internal;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.config.CesecoreConfigurationHelper;
import org.cesecore.internal.InternalResources;
import org.cesecore.util.CertTools;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.ValidityDateUtil;

/**
 * Class used to construct validity times based on a range of different input
 * parameters and configuration.
 *
 * @version $Id: CertificateValidity.java 28114 2018-01-26 14:51:20Z samuellb $
 */
public class CertificateValidity {

  /** 24. */
  private static final int HOURS_PER_DAY = 24;
  /** 60. */
  private static final int MINS_PER_HOUR = 60;
  /** 60. */
  private static final int SECS_PER_MIN = 60;
  /** 1000. */
  private static final int MS_PER_SEC = 1000;

  /** Class logger. */
  private static final Logger LOG = Logger.getLogger(CertificateValidity.class);

  /** Internal localization of logs and errors. */
  private static final InternalResources INTRES =
      InternalResources.getInstance();

  /**
   * Issuing certificates with 'notAfter' greater than this value throws an
   * exception.
   */
  private static Date tooLateExpireDate;
  /** The certificates 'notAfter' value. */
  private Date lastDate;

  /** The certificates 'notBefore' value. */
  private Date firstDate;


  static {
    final String value = CesecoreConfigurationHelper.getCaTooLateExpireDate();
    try {
      tooLateExpireDate = ValidityDateUtil.parseCaLatestValidDateTime(value);
    } catch (Exception e) {
      final String newValue =
          ValidityDateUtil.formatAsISO8601(
              new Date(Long.MAX_VALUE), ValidityDateUtil.TIMEZONE_SERVER);
      tooLateExpireDate = ValidityDateUtil.parseCaLatestValidDateTime(newValue);
      LOG.warn(
          "cesecore.properties ca.toolateexpiredate '"
              + value
              + "' could not be parsed Using default value '"
              + newValue
              + "'.",
          e);
    }
  }

  /**
   * Validity offset in milliseconds (offset for the 'notBefore' value) The
   * default start date is set 10 minutes back to avoid some problems with
   * unsynchronized clocks.
   */
  private static long defaultValidityOffset;

  static {
    final String value =
            CesecoreConfigurationHelper.getCertificateValidityOffset();
    try {
      defaultValidityOffset =
          SimpleTime.getSecondsFormat().parseMillis(value);
    } catch (Exception e) {
      // Use old value for compatibility reasons!
      defaultValidityOffset = -10L * SECS_PER_MIN * MS_PER_SEC;
      LOG.warn(
          "cesecore.properties certificate.validityoffset '"
              + value
              + "' could not be parsed as relative time string. Using default"
              + " value '-10m' = -60000ms",
          e);
    }
  }

  /**
   * Gets the default validity offset.
   *
   * @return the offset as relative time.
   * @see org.cesecore.util.SimpleTime SimpleTime
   */
  public static final long getValidityOffset() {
    return defaultValidityOffset;
  }

  /**
   * Gets the maximum possible value for the certificates 'notAfter' value.
   *
   * @return ISO8601 date
   */
  public static Date getToolLateExpireDate() {
    return tooLateExpireDate;
  }

  /**
   * Sets the maximum possible value for the certificates 'notAfter' value. This
   * method MUST NOT BE CALLED, except for unit testing.
   *
   * @param date the date to set.
   */
  public static void setTooLateExpireDate(final Date date) {
    tooLateExpireDate = date;
  }

  /** Constructor.
   *
   * @param subject Subject
   * @param certProfile DN
   * @param notBefore Date
   * @param notAfter Date
   * @param cacert CA cert
   * @param isRootCA Bool
   * @param isLinkCertificate Bool
   * @throws IllegalValidityException Fail
   */
  public CertificateValidity(
      final EndEntityInformation subject,
      final CertificateProfile certProfile,
      final Date notBefore,
      final Date notAfter,
      final Certificate cacert,
      final boolean isRootCA,
      final boolean isLinkCertificate)
      throws IllegalValidityException {
    this(
        new Date(),
        subject,
        certProfile,
        notBefore,
        notAfter,
        cacert,
        isRootCA,
        isLinkCertificate);
  }

  /**
   * Constructor that injects the reference point (now). This constructor mainly
   * is used for unit testing.
   *
   * @param now Now
   * @param subject Subject
   * @param certProfile Profila
   * @param notBefore Start date
   * @param notAfter End date
   * @param cacert CA Certificate
   * @param isRootCA bool
   * @param isLinkCertificate bool
   * @throws IllegalValidityException on fail
   */
  public CertificateValidity(
      final Date now,
      final EndEntityInformation subject,
      final CertificateProfile certProfile,
      final Date notBefore,
      final Date notAfter,
      final Certificate cacert,
      final boolean isRootCA,
      final boolean isLinkCertificate)
      throws IllegalValidityException {
    logStartConstruct(subject, certProfile, notBefore, notAfter);
    if (tooLateExpireDate == null) {
      throw new IllegalStateException(
          "ca.toolateexpiredate in cesecore.properties is not a valid date.");
    }

    // ECA-3554 add the offset

    Date newNow = getNowWithOffset(now, certProfile);
    if (LOG.isDebugEnabled()) {
      LOG.debug("Using new start time including offset: " + newNow);
    }

    // Find out what start and end time to actually use..
    setFirstAndLastDate(subject, certProfile, notBefore, notAfter, newNow);
    // Third priority: If nothing could be set by external information have the
    // default  3 is default values
    if (firstDate == null) {
      firstDate = newNow;
    }
    Date certProfileLastDate = getLastDate(certProfile);
    // If it is a link certificate that we create, we use the old ca's expire
    // date, as requested, as link certificate expire date
    if (isLinkCertificate) {
      lastDate = notAfter;
    }
    if (lastDate == null) {
      lastDate = certProfileLastDate;
    }
    // Limit validity: Do not allow last date to be before first date
    limitValidityBeforeFirst();
    // Limit validity: We do not allow a certificate to be valid before the
    // current date, i.e. not back dated start dates
    // Unless allowValidityOverride is set, then we allow everything
    // So this check is probably completely unneeded and can never be true
    certProfileLastDate = limitValidityBeforeNow(subject,
            certProfile, newNow, certProfileLastDate);
    // Limit validity: We do not allow a certificate to be valid after the the
    // validity of the certificate profile
    limitValidityAfterProfile(subject, certProfileLastDate);
    // Limit validity: We do not allow a certificate to be valid after the the
    // validity of the CA (unless it's RootCA during renewal)
    limitValidityNotAfter(cacert, isRootCA);
    // Limit validity: We do not allow a certificate to be valid before the the
    // CA becomes valid (unless it's RootCA during renewal)
    limitValidityNotBefore(cacert, isRootCA);
  }

/**
 *
 */
private void limitValidityBeforeFirst() {
    if (lastDate.before(firstDate)) {
      LOG.info(
          INTRES.getLocalizedMessage(
              "createcert.errorinvalidcausality", firstDate, lastDate));
      Date tmp = lastDate;
      lastDate = firstDate;
      firstDate = tmp;
    }
}

/**
 * @param subject subj
 * @param certProfile profile
 * @param newNow now
 * @param alastDate date
 * @return date
 */
private Date limitValidityBeforeNow(final EndEntityInformation subject,
        final CertificateProfile certProfile,
        final Date newNow, final Date alastDate) {
    Date newLastDate = alastDate;
    if (firstDate.before(newNow) && !certProfile.getAllowValidityOverride()) {
      LOG.error(
          INTRES.getLocalizedMessage(
              "createcert.errorbeforecurrentdate",
              firstDate,
              subject.getUsername()));
      firstDate = newNow;
      // Update valid length from the profile since the starting point has
      // changed
      newLastDate =
          new Date(getCertificateProfileValidtyEndDate(certProfile, firstDate));
      // Update lastDate if we use maximum validity
    }
    return newLastDate;
}

/**
 * @param subject subj
 * @param certProfileLastDate date
 */
private void limitValidityAfterProfile(final EndEntityInformation subject,
        final Date certProfileLastDate) {
    if (lastDate.after(certProfileLastDate)) {
      LOG.info(
          INTRES.getLocalizedMessage(
              "createcert.errorbeyondmaxvalidity",
              lastDate,
              subject.getUsername(),
              certProfileLastDate));
      lastDate = certProfileLastDate;
    }
}

/**
 * @param cacert cert
 * @param isRootCA bool
 */
private void limitValidityNotAfter(final Certificate cacert,
        final boolean isRootCA) {
    if (cacert != null && !isRootCA) {
      final Date caNotAfter = CertTools.getNotAfter(cacert);
      if (lastDate.after(caNotAfter)) {
        LOG.info(
            INTRES.getLocalizedMessage(
                "createcert.limitingvalidity",
                lastDate.toString(),
                caNotAfter));
        lastDate = caNotAfter;
      }
    }
}

/**
 * @param subject subject
 * @param certProfile profile
 * @param notBefore date
 * @param notAfter date
 * @param newNow date
 */
private void setFirstAndLastDate(final EndEntityInformation subject,
        final CertificateProfile certProfile,
        final Date notBefore, final Date notAfter, final Date newNow) {
    if (certProfile.getAllowValidityOverride()) {
      // First Priority has information supplied in Extended information object.
      // This allows RA-users to set the time-span.
      // Second Priority has the information supplied in the method arguments
      firstDate = getExtendedInformationStartTime(newNow, subject);
      if (firstDate == null) {
        firstDate = notBefore;
      }
      lastDate = getExtendedInformationEndTime(newNow, subject);
      if (lastDate == null) {
        lastDate = notAfter;
      }
      if (LOG.isDebugEnabled()) {
        LOG.debug("Allow validity override, notBefore: " + firstDate);
        LOG.debug("Allow validity override, notAfter: " + lastDate);
      }
    }
}

/**
 * @param cacert cert
 * @param isRootCA bool
 * @throws IllegalValidityException fail
 */
private void limitValidityNotBefore(final Certificate cacert,
        final boolean isRootCA) throws IllegalValidityException {
    if (cacert != null && !isRootCA) {
      final Date caNotBefore = CertTools.getNotBefore(cacert);
      if (firstDate.before(caNotBefore)) {
        LOG.info(
            INTRES.getLocalizedMessage(
                "createcert.limitingvaliditystart",
                firstDate.toString(),
                caNotBefore));
        firstDate = caNotBefore;
      }
    }
    if (!lastDate.before(CertificateValidity.tooLateExpireDate)) {
      String msg =
          INTRES.getLocalizedMessage(
              "createcert.errorbeyondtoolateexpiredate",
              lastDate.toString(),
              CertificateValidity.tooLateExpireDate.toString());
      LOG.info(msg);
      throw new IllegalValidityException(msg);
    }
}

/**
 * @param certProfile profile
 * @return date
 */
private Date getLastDate(final CertificateProfile certProfile) {
    Date certProfileLastDate =
        new Date(getCertificateProfileValidtyEndDate(certProfile, firstDate));
    // Limit validity: ECA-5330 Apply expiration restriction for weekdays
    if (certProfile.getUseExpirationRestrictionForWeekdays()
        && isRelativeTime(certProfile.getEncodedValidity())) {
      LOG.info(
          "Applying expiration restrictions for weekdays: "
              + Arrays.asList(certProfile.getExpirationRestrictionWeekdays()));
      try {
        final Date newDate =
            ValidityDateUtil.applyExpirationRestrictionForWeekdays(
                certProfileLastDate,
                certProfile.getExpirationRestrictionWeekdays(),
                certProfile.getExpirationRestrictionForWeekdaysExpireBefore());
        if (!firstDate.before(newDate)) {
          LOG.warn(
              "Expiration restriction of certificate profile could not be"
                  + " applied because it's before start date!");
        } else if (!tooLateExpireDate.after(newDate)) {
          LOG.warn(
              "Expiration restriction of certificate profile could not be"
                  + " applied because it's after latest possible end date!");
        } else {
          certProfileLastDate = newDate;
        }
      } catch (Exception e) {
        LOG.warn(
            "Expiration restriction of certificate profile could not be"
                + " applied!");
      }
    }
    return certProfileLastDate;
}

/**
 * @param subject Subject
 * @param certProfile Profile
 * @param notBefore DAte
 * @param notAfter Date
 */
private void logStartConstruct(final EndEntityInformation subject,
        final CertificateProfile certProfile,
        final Date notBefore, final Date notAfter) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Requested notBefore: " + notBefore);
      LOG.debug("Requested notAfter: " + notAfter);
      if (null != subject.getExtendedInformation()) {
        LOG.debug(
            "End entity extended information 'notBefore': "
                + subject
                    .getExtendedInformation()
                    .getCustomData(ExtendedInformation.CUSTOM_STARTTIME));
      }
      if (null != subject.getExtendedInformation()) {
        LOG.debug(
            "End entity extended information 'notAfter': "
                + subject
                    .getExtendedInformation()
                    .getCustomData(ExtendedInformation.CUSTOM_ENDTIME));
      }
      LOG.debug("Default validty offset: " + defaultValidityOffset);
      LOG.debug(
          "Certificate profile validty: " + certProfile.getEncodedValidity());
      LOG.debug(
          "Certificate profile use validty offset: "
              + certProfile.getUseCertificateValidityOffset());
      LOG.debug(
          "Certificate profile validty offset: "
              + certProfile.getCertificateValidityOffset());
      LOG.debug(
          "Certificate profile use expiration restrictions for weekdays: "
              + certProfile.getUseExpirationRestrictionForWeekdays());
      LOG.debug(
          "Certificate profile expiration restrictions weekdays: "
              + Arrays.toString(
                  certProfile.getExpirationRestrictionWeekdays()));
      LOG.debug(
          "Certificate profile expiration restrictions for weekdays before: "
              + certProfile.getExpirationRestrictionForWeekdaysExpireBefore());
    }
}

  /**
   * Gets the certificates 'notAter' value.
   *
   * @return the 'notAfter' date.
   */
  public Date getNotAfter() {
    return lastDate;
  }

  /**
   * Gets the certificates 'notBefore' value.
   *
   * @return the 'notBefore' date.
   */
  public Date getNotBefore() {
    return firstDate;
  }

  /**
   * Gets the validity end date for the certificate using the certificate
   * profiles encoded validity.
   *
   * @param profile the certificate profile
   * @param aFirstDate the start time.
   * @return the encoded validity.
   */
  @SuppressWarnings("deprecation")
  private long getCertificateProfileValidtyEndDate(
      final CertificateProfile profile, final  Date aFirstDate) {
    final String encodedValidity = profile.getEncodedValidity();
    Date date = null;
    if (StringUtils.isNotBlank(encodedValidity)) {
      date = ValidityDateUtil.getDate(encodedValidity, aFirstDate);
    } else {
      date =
          ValidityDateUtil.getDateBeforeVersion661(
              profile.getValidity(), aFirstDate);
    }
    return date.getTime();
  }

  /**
   * Offsets the certificates 'notBefore' (reference point) with the global
   * offset or the offset of the certificate profile.
   *
   * @param now the reference point
   * @param profile the certificate profile
   * @return the offset reference point
   */
  private Date getNowWithOffset(
      final Date now, final CertificateProfile profile) {
    Date result = null;
    if (profile.getUseCertificateValidityOffset()) {
      final String offset = profile.getCertificateValidityOffset();
      try {
        result = new Date(now.getTime() + SimpleTime.parseMillies(offset));
        if (LOG.isDebugEnabled()) {
          LOG.debug("Using validity offset by certificate profile: " + offset);
        }
      } catch (NumberFormatException e) {
        LOG.warn(
            "Could not parse certificate validity offset "
                + offset
                + "; using default "
                + defaultValidityOffset);
      }
    } else {
      result = new Date(now.getTime() + defaultValidityOffset);
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Using validity offset by cesecore.properties: "
                + SimpleTime.toString(
                    defaultValidityOffset, SimpleTime.TYPE_DAYS));
      }
    }
    return result;
  }

  /**
   * Gets the start time by the extended entity information.
   *
   * @param now the reference point.
   * @param subject the end entity information.
   * @return Start time
   */
  private Date getExtendedInformationStartTime(
      final Date now, final EndEntityInformation subject) {
    Date result = null;
    final ExtendedInformation extendedInformation =
        subject.getExtendedInformation();
    if (extendedInformation != null) {
      result =
          parseExtendedInformationEncodedValidity(
              now,
              extendedInformation.getCustomData(
                  ExtendedInformation.CUSTOM_STARTTIME));
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Using ExtendedInformationStartTime: " + result);
    }
    return result;
  }

  /**
   * Gets the end time by the extended entity information.
   *
   * @param now the reference point.
   * @param subject the end entity information.
   * @return End time
   */
  private Date getExtendedInformationEndTime(
      final Date now, final EndEntityInformation subject) {
    Date result = null;
    final ExtendedInformation extendedInformation =
        subject.getExtendedInformation();
    if (extendedInformation != null) {
      result =
          parseExtendedInformationEncodedValidity(
              now,
              extendedInformation.getCustomData(
                  ExtendedInformation.CUSTOM_ENDTIME));
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Using ExtendedInformationEndTime: " + result);
    }
    return result;
  }

  /**
   * Checks that the PrivateKeyUsagePeriod of the certificate is valid at this
   * time.
   *
   * @param cert Certificate
   * @throws CAOfflineException if PrivateKeyUsagePeriod either is not valid yet
   *     or has expired, exception message gives details
   */
  public static void checkPrivateKeyUsagePeriod(final X509Certificate cert)
      throws CAOfflineException {
    checkPrivateKeyUsagePeriod(cert, new Date());
  }

  /**
   *
   * @param cert Certificate
   * @param checkDate Date
   * @throws CAOfflineException Fail
   */
  public static void checkPrivateKeyUsagePeriod(
      final X509Certificate cert, final Date checkDate)
      throws CAOfflineException {
    if (cert != null) {
      final PrivateKeyUsagePeriod pku =
          CertTools.getPrivateKeyUsagePeriod(cert);
      if (pku != null) {
        final ASN1GeneralizedTime notBefore = pku.getNotBefore();
        final Date pkuNotBefore;
        final Date pkuNotAfter;
        try {
          if (notBefore == null) {
            pkuNotBefore = null;
          } else {
            pkuNotBefore = notBefore.getDate();
          }
          if (LOG.isDebugEnabled()) {
            LOG.debug("PrivateKeyUsagePeriod.notBefore is " + pkuNotBefore);
          }
          handleNotBefore(cert, checkDate, pkuNotBefore);
          final ASN1GeneralizedTime notAfter = pku.getNotAfter();

          if (notAfter == null) {
            pkuNotAfter = null;
          } else {
            pkuNotAfter = notAfter.getDate();
          }
        } catch (ParseException e) {
          throw new IllegalStateException("Could not parse dates.", e);
        }
        if (LOG.isDebugEnabled()) {
          LOG.debug("PrivateKeyUsagePeriod.notAfter is " + pkuNotAfter);
        }
        handleNotAfter(cert, checkDate, pkuNotAfter);
      } else if (LOG.isDebugEnabled()) {
        LOG.debug("No PrivateKeyUsagePeriod available in certificate.");
      }
    } else if (LOG.isDebugEnabled()) {
      LOG.debug(
          "No CA certificate available, not checking PrivateKeyUsagePeriod.");
    }
  }

/**
 * @param cert cert
 * @param checkDate date
 * @param pkuNotAfter notAfter
 * @throws CAOfflineException fail
 */
private static void handleNotAfter(final X509Certificate cert,
        final Date checkDate, final Date pkuNotAfter)
        throws CAOfflineException {
    if (pkuNotAfter != null && checkDate.after(pkuNotAfter)) {
      final String msg =
          INTRES.getLocalizedMessage(
              "createcert.privatekeyusageexpired",
              pkuNotAfter.toString(),
              cert.getSubjectDN().toString());
      if (LOG.isDebugEnabled()) {
        LOG.debug(msg);
      }
      throw new CAOfflineException(msg);
    }
}

/**
 * @param cert cert
 * @param checkDate date
 * @param pkuNotBefore notBefore
 * @throws CAOfflineException Fail
 */
private static void handleNotBefore(final X509Certificate cert,
        final Date checkDate, final Date pkuNotBefore)
        throws CAOfflineException {
    if (pkuNotBefore != null && checkDate.before(pkuNotBefore)) {
        final String msg =
            INTRES.getLocalizedMessage(
                "createcert.privatekeyusagenotvalid",
                pkuNotBefore.toString(),
                cert.getSubjectDN().toString());
        if (LOG.isDebugEnabled()) {
          LOG.debug(msg);
        }
        throw new CAOfflineException(msg);
      }
}

  /**
   * Checks if the encoded validity is an ISO8601 date or a relative time.
   *
   * @param encodedValidity the validity
   * @return Boolean.TRUE if it is a relative time, Boolean.FALSE if it is an
   *     ISO8601 date, otherwise NULL. @See {@link
   *     org.cesecore.util.ValidityDateUtil ValidityDate} @See {@link
   *     org.cesecore.util.SimpleTime SimpleTime}
   */
  private static Boolean isRelativeTime(final String encodedValidity) {
    try {
      // Try the most likely setting first, for fail-fast
      SimpleTime.parseMillies(encodedValidity);
      return Boolean.TRUE;
    } catch (NumberFormatException nfe) { // NOPMD this is a no-op
    }
    try {
      ValidityDateUtil.parseAsIso8601(encodedValidity);
      return Boolean.FALSE;
    } catch (ParseException e) {
      return null;
    }
  }

  /**
   * Parses the entity extended information start and end time format and
   * offsets it with the reference point.
   *
   * @param now the reference point
   * @param timeString the value in form of 'days:hours:minutes'
   * @return the parse value offset with now (reference point).
   */
  private static Date parseExtendedInformationEncodedValidity(
      final Date now, final String timeString) {
    Date result = null;
    if (timeString != null) {
      if (timeString.matches("^\\d+:\\d?\\d:\\d?\\d$")) {
        final String[] endTimeArray = timeString.split(":");
        long relative =
            (Long.parseLong(endTimeArray[0]) * HOURS_PER_DAY * MINS_PER_HOUR
                    + Long.parseLong(endTimeArray[1]) * MINS_PER_HOUR
                    + Long.parseLong(endTimeArray[2]))
                * SECS_PER_MIN
                * MS_PER_SEC;
        result = new Date(now.getTime() + relative);
      } else {
        try {
          // Try parsing data as "yyyy-MM-dd HH:mm" assuming UTC
          result = ValidityDateUtil.parseAsUTC(timeString);
        } catch (ParseException e) {
          LOG.error(
              INTRES.getLocalizedMessage(
                  "createcert.errorinvalidstarttime", timeString));
        }
      }
      if (LOG.isDebugEnabled()) {
        LOG.debug("Time string by end entity extended Information: " + result);
      }
    }
    return result;
  }
}
