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
package org.ejbca.core.model.era;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang.builder.HashCodeBuilder;

/**
 * Search request for certificates from RA UI.
 *
 * @version $Id: RaCertificateSearchRequest.java 26524 2017-09-11 09:12:49Z
 *     bastianf $
 */
public class RaCertificateSearchRequest
    implements Serializable, Comparable<RaCertificateSearchRequest> {

  private static final long serialVersionUID = 1L;
  // private static final Logger log =
  // Logger.getLogger(RaCertificateSearchRequest.class);
  /** Param. */
  public static final int DEFAULT_MAX_RESULTS = 25;

  /** Param. */
  private int maxResults = DEFAULT_MAX_RESULTS;
  /** Param. */
  private int pageNumber = 0;
  /** Param. */
  private List<Integer> eepIds = new ArrayList<>();
  /** Param. */
  private List<Integer> cpIds = new ArrayList<>();
  /** Param. */
  private List<Integer> caIds = new ArrayList<>();
  /** Param. */
  private String subjectDnSearchString = "";
  /** Param. */
  private boolean subjectDnSearchExact = false;
  /** Param. */
  private String subjectAnSearchString = "";
  /** Param. */
  private boolean subjectAnSearchExact = false;
  /** Param. */
  private String usernameSearchString = "";
  /** Param. */
  private boolean usernameSearchExact = false;
  /** Param. */
  private String serialNumberSearchStringFromDec = "";
  /** Param. */
  private String serialNumberSearchStringFromHex = "";
  /** Param. */
  private long issuedAfter = 0L;
  /** Param. */
  private long issuedBefore = Long.MAX_VALUE;
  /** Param. */
  private long expiresAfter = 0L;
  /** Param. */
  private long expiresBefore = Long.MAX_VALUE;
  /** Param. */
  private long revokedAfter = 0L;
  /** Param. */
  private long revokedBefore = Long.MAX_VALUE;
  /** Param. */
  private List<Integer> statuses = new ArrayList<>();
  /** Param. */
  private List<Integer> revocationReasons = new ArrayList<>();

  /** Default constructor. */
  public RaCertificateSearchRequest() { }

  /**
   * Copy constructor.
   *
   * @param request req
   */
  public RaCertificateSearchRequest(final RaCertificateSearchRequest request) {
    maxResults = request.maxResults;
    pageNumber = request.pageNumber;
    eepIds.addAll(request.eepIds);
    cpIds.addAll(request.cpIds);
    caIds.addAll(request.caIds);
    subjectDnSearchString = request.subjectDnSearchString;
    subjectDnSearchExact = request.subjectDnSearchExact;
    subjectAnSearchString = request.subjectAnSearchString;
    subjectAnSearchExact = request.subjectAnSearchExact;
    usernameSearchString = request.usernameSearchString;
    usernameSearchExact = request.usernameSearchExact;
    serialNumberSearchStringFromDec = request.serialNumberSearchStringFromDec;
    serialNumberSearchStringFromHex = request.serialNumberSearchStringFromHex;
    issuedAfter = request.issuedAfter;
    issuedBefore = request.issuedBefore;
    expiresAfter = request.expiresAfter;
    expiresBefore = request.expiresBefore;
    revokedAfter = request.revokedAfter;
    revokedBefore = request.revokedBefore;
    statuses.addAll(request.statuses);
    revocationReasons.addAll(request.revocationReasons);
  }

  /**
   * @return max
   */
  public int getMaxResults() {
    return maxResults;
  }

  /**
   * @return page
   */
  public int getPageNumber() {
    return pageNumber;
  }

  /**
   * @param apageNumber page
   */
  public void setPageNumber(final int apageNumber) {
    this.pageNumber = apageNumber;
  }


  /**
   * @param amaxResults Max
   */
  public void setMaxResults(final int amaxResults) {
    this.maxResults = amaxResults;
  }

  /**
   * Reset.
   */
  public void resetMaxResults() {
    this.maxResults = DEFAULT_MAX_RESULTS;
  }

  /**
   * @return IDs
   */
  public List<Integer> getEepIds() {
    return eepIds;
  }


  /**
   * @param aneepIds IDs
   */
  public void setEepIds(final List<Integer> aneepIds) {
    this.eepIds = aneepIds;
  }

  /**
   * @return IDs
   */
  public List<Integer> getCpIds() {
    return cpIds;
  }

  /**
   * @param thecpIds IDs
   */
  public void setCpIds(final List<Integer> thecpIds) {
    this.cpIds = thecpIds;
  }

  /**
   * @return IDs
   */
  public List<Integer> getCaIds() {
    return caIds;
  }

  /**
   * @param thecaIds IDs
   */
  public void setCaIds(final List<Integer> thecaIds) {
    this.caIds = thecaIds;
  }

  /**
   * @return search
   */
  public String getSubjectDnSearchString() {
    return subjectDnSearchString;
  }

  /**
   * @param asubjectDnSearchString search
   */
  public void setSubjectDnSearchString(final String asubjectDnSearchString) {
    this.subjectDnSearchString = asubjectDnSearchString;
  }

  /**
   * @return bool
   */
  public boolean isSubjectDnSearchExact() {
    return subjectDnSearchExact;
  }

  /**
   * @param issubjectDnSearchExact bool
   */
  public void setSubjectDnSearchExact(final boolean issubjectDnSearchExact) {
    this.subjectDnSearchExact = issubjectDnSearchExact;
  }

  /**
   * @return search
   */
  public String getSubjectAnSearchString() {
    return subjectAnSearchString;
  }

  /**
   * @param asubjectAnSearchString search
   */
  public void setSubjectAnSearchString(final String asubjectAnSearchString) {
    this.subjectAnSearchString = asubjectAnSearchString;
  }

  /**
   * @return bool
   */
  public boolean isSubjectAnSearchExact() {
    return subjectAnSearchExact;
  }

  /**
   * @param issubjectAnSearchExact bool
   */
  public void setSubjectAnSearchExact(final boolean issubjectAnSearchExact) {
    this.subjectAnSearchExact = issubjectAnSearchExact;
  }


  /**
   * @return search
   */
  public String getUsernameSearchString() {
    return usernameSearchString;
  }

  /**
   * @param ausernameSearchString search
   */
  public void setUsernameSearchString(final String ausernameSearchString) {
    this.usernameSearchString = ausernameSearchString;
  }

  /**
   * @return bool
   */
  public boolean isUsernameSearchExact() {
    return usernameSearchExact;
  }

  /**
   * @param isusernameSearchExact bool
   */
  public void setUsernameSearchExact(final boolean isusernameSearchExact) {
    this.usernameSearchExact = isusernameSearchExact;
  }

  /**
   * @return searchn
   */
  public String getSerialNumberSearchStringFromDec() {
    return serialNumberSearchStringFromDec;
  }
  /**
   * Set the serialNumber search string as a decimal String if it has potential
   * to be a decimal certificate serial number.
   *
   * @param aserialNumberSearchStringFromDec sn
   */
  public void setSerialNumberSearchStringFromDec(
      final String aserialNumberSearchStringFromDec) {
    // Assuming 8 octets and some leading zeroes
    String value = "";
    if (aserialNumberSearchStringFromDec.length() >= 16) {
      try {
        value =
            new BigInteger(aserialNumberSearchStringFromDec, 10).toString(10);
      } catch (NumberFormatException e) {
      }
    }
    this.serialNumberSearchStringFromDec = value;
  }

  /**
   * @return search
   */
  public String getSerialNumberSearchStringFromHex() {
    return serialNumberSearchStringFromHex;
  }
  /**
   * Set the serialNumber search string as a decimal String if it has potential
   * to be a hex certificate serial number.
   *
   * @param aserialNumberSearchStringFromHex sn
   */
  public void setSerialNumberSearchStringFromHex(
      final String aserialNumberSearchStringFromHex) {
    // Assuming 8 octets and some leading zeroes
    String value = "";
    final int maxLen = 14;
    if (aserialNumberSearchStringFromHex.length() >= maxLen) {
      try {
        value =
            new BigInteger(aserialNumberSearchStringFromHex, 16).toString(10);
      } catch (NumberFormatException e) {
      }
    }
    this.serialNumberSearchStringFromHex = value;
  }

  /**
   * @return long
   */
  public long getIssuedAfter() {
    return issuedAfter;
  }

  /**
   * @param anissuedAfter long
   */
  public void setIssuedAfter(final long anissuedAfter) {
    this.issuedAfter = anissuedAfter;
  }

  /**
   * @return bool
   */
  public boolean isIssuedAfterUsed() {
    return issuedAfter > 0L;
  }

  /** Reset. */
  public void resetIssuedAfter() {
    this.issuedAfter = 0L;
  }

  /**
   * @return long
   */
  public long getIssuedBefore() {
    return issuedBefore;
  }

  /**
   * @param anissuedBefore long
   */
  public void setIssuedBefore(final long anissuedBefore) {
    this.issuedBefore = anissuedBefore;
  }

  /**
   * @return bool
   */
  public boolean isIssuedBeforeUsed() {
    return issuedBefore < Long.MAX_VALUE;
  }

  /**
   * Reset.
   */
  public void resetIssuedBefore() {
    this.issuedBefore = Long.MAX_VALUE;
  }

  /**
   * @return long
   */
  public long getExpiresAfter() {
    return expiresAfter;
  }

  /**
   * @param anexpiresAfter long
   */
  public void setExpiresAfter(final long anexpiresAfter) {
    this.expiresAfter = anexpiresAfter;
  }

  /**
   * @return bool
   */
  public boolean isExpiresAfterUsed() {
    return expiresAfter > 0L;
  }

  /** Reset.
   */
  public void resetExpiresAfter() {
    this.expiresAfter = 0L;
  }

  /**
   * @return long
   */
  public long getExpiresBefore() {
    return expiresBefore;
  }

  /**
   * @param anexpiresBefore long
   */
  public void setExpiresBefore(final long anexpiresBefore) {
    this.expiresBefore = anexpiresBefore;
  }

  /**
   * @return bool
   */
  public boolean isExpiresBeforeUsed() {
    return expiresBefore < Long.MAX_VALUE;
  }

  /** Reset. */
  public void resetExpiresBefore() {
    this.expiresBefore = Long.MAX_VALUE;
  }

  /**
   * @return long
   */
  public long getRevokedAfter() {
    return revokedAfter;
  }

  /**
   * @param arevokedAfter long
   */
  public void setRevokedAfter(final long arevokedAfter) {
    this.revokedAfter = arevokedAfter;
  }

  /**
   * @return bool
   */
  public boolean isRevokedAfterUsed() {
    return revokedAfter > 0L;
  }

  /** Reset. */
  public void resetRevokedAfter() {
    this.revokedAfter = 0L;
  }

  /**
   * @return revoked
   */
  public long getRevokedBefore() {
    return revokedBefore;
  }

  /**
   * @param isrevokedBefore long
   */
  public void setRevokedBefore(final long isrevokedBefore) {
    this.revokedBefore = isrevokedBefore;
  }

  /**
   * @return bool
   */
  public boolean isRevokedBeforeUsed() {
    return revokedBefore < Long.MAX_VALUE;
  }

  /** Reset. */
  public void resetRevokedBefore() {
    this.revokedBefore = Long.MAX_VALUE;
  }

  /**
   * @return statuses
   */
  public List<Integer> getStatuses() {
    return statuses;
  }

  /**
   * @param thestatuses statuses
   */
  public void setStatuses(final List<Integer> thestatuses) {
    this.statuses = thestatuses;
  }

  /**
   * @return reasons
   */
  public List<Integer> getRevocationReasons() {
    return revocationReasons;
  }

  /**
   * @param therevocationReasons reasons
   */
  public void setRevocationReasons(final List<Integer> therevocationReasons) {
    this.revocationReasons = therevocationReasons;
  }

  @Override
  public int hashCode() {
    return HashCodeBuilder.reflectionHashCode(this);
  }

  @Override
  public boolean equals(final Object object) {
    if (!(object instanceof RaCertificateSearchRequest)) {
      return false;
    }
    final RaCertificateSearchRequest request =
        (RaCertificateSearchRequest) object;
    return compareTo(request) == 0
        && request.getPageNumber() == this.pageNumber;
  }

  // negative = this object is less (more narrow) than other. E.g. only when
  // other contains this and more.
  // positive = this object is greater (wider) than other
  // zero = this object is equal to other
  @Override
  public int compareTo(final RaCertificateSearchRequest other) {
    if (other == null) {
      return 1;
    }
    // First check if there is any there is any indication that this does not
    // contain the whole other
    if (maxResults > other.maxResults
        || isWider(eepIds, other.eepIds)
        || isWider(cpIds, other.cpIds)
        || isWider(caIds, other.caIds)
        || issuedAfter < other.issuedAfter
        || issuedBefore > other.issuedBefore
        || expiresAfter < other.expiresAfter
        || expiresBefore > other.expiresBefore
        || revokedAfter < other.revokedAfter
        || revokedBefore > other.revokedBefore
        || isWider(subjectDnSearchString, other.subjectDnSearchString)
        || isWider(subjectDnSearchExact, other.subjectDnSearchExact)
        || isWider(subjectAnSearchString, other.subjectAnSearchString)
        || isWider(subjectAnSearchExact, other.subjectAnSearchExact)
        || isWider(usernameSearchString, other.usernameSearchString)
        || isWider(usernameSearchExact, other.usernameSearchExact)
        || isWider(
            serialNumberSearchStringFromDec,
            other.serialNumberSearchStringFromDec)
        || isWider(
            serialNumberSearchStringFromHex,
            other.serialNumberSearchStringFromHex)
        || isWider(statuses, other.statuses)
        || isWider(revocationReasons, other.revocationReasons)) {
      // This does not contain whole other → wider
      return 1;
    }
    // Next check if this object is more narrow than the other
    if (maxResults < other.maxResults
        || isMoreNarrow(eepIds, other.eepIds)
        || isMoreNarrow(cpIds, other.cpIds)
        || isMoreNarrow(caIds, other.caIds)
        || issuedAfter > other.issuedAfter
        || issuedBefore < other.issuedBefore
        || expiresAfter > other.expiresAfter
        || expiresBefore < other.expiresBefore
        || revokedAfter > other.revokedAfter
        || revokedBefore < other.revokedBefore
        || isMoreNarrow(subjectDnSearchString, other.subjectDnSearchString)
        || isMoreNarrow(subjectDnSearchExact, other.subjectDnSearchExact)
        || isMoreNarrow(subjectAnSearchString, other.subjectAnSearchString)
        || isMoreNarrow(subjectAnSearchExact, other.subjectAnSearchExact)
        || isMoreNarrow(usernameSearchString, other.usernameSearchString)
        || isMoreNarrow(usernameSearchExact, other.usernameSearchExact)
        || isMoreNarrow(
            serialNumberSearchStringFromDec,
            other.serialNumberSearchStringFromDec)
        || isMoreNarrow(
            serialNumberSearchStringFromHex,
            other.serialNumberSearchStringFromHex)
        || isMoreNarrow(statuses, other.statuses)
        || isMoreNarrow(revocationReasons, other.revocationReasons)) {
      // This does contain whole other, but other does not contain whole this →
      // more narrow
      return -1;
    }
    return 0;
  }

  /**
   * @param thisObject obj
   * @param otherObject obj
   * @return true if thisObject does contain whole other, but other does not
   *     contain whole this → more narrow
   */
  private boolean isMoreNarrow(
      final List<Integer> thisObject, final List<Integer> otherObject) {
    return thisObject.containsAll(otherObject)
        && !otherObject.containsAll(thisObject);
  }
  /**
   * @param thisObject obj
   * @param otherObject obj
   * @return true if thisObject does contain whole other, but other does not
   *     contain whole this → more narrow
   */
  private boolean isMoreNarrow(
      final String thisObject, final String otherObject) {
    return thisObject.contains(otherObject)
        && !otherObject.contains(thisObject);
  }
  /**
   * @param thisObjectExact obj
   * @param otherObjectExact ong
   * @return true if thisObject does contain whole other, but other does not
   *     contain whole this → more narrow
   */
  private boolean isMoreNarrow(
      final boolean thisObjectExact, final boolean otherObjectExact) {
    return thisObjectExact && !otherObjectExact;
  }
  /**
   * @param thisObject obj
   * @param otherObject obj
   * @return true if thisObject does not contain whole other → wider
   */
  private boolean isWider(
      final List<Integer> thisObject, final List<Integer> otherObject) {
    return !thisObject.containsAll(otherObject);
  }
  /**
   * @param thisObject obj
   * @param otherObject obj
   * @return true if thisObject does not contain whole other → wider
   */
  private boolean isWider(final String thisObject, final String otherObject) {
    return !thisObject.contains(otherObject);
  }
  /**
   * @param thisObjectExact obj
   * @param otherObjectExact obj
   * @return true if thisObject does not contain whole other → wider
   */
  private boolean isWider(
      final boolean thisObjectExact, final boolean otherObjectExact) {
    return !thisObjectExact && otherObjectExact;
  }

  /**
   * @param endEntityProfileId ID
   * @return true if the endEntityProfileId is matched by this search.
   */
  public boolean matchEep(final int endEntityProfileId) {
    return eepIds.isEmpty()
        || eepIds.contains(Integer.valueOf(endEntityProfileId));
  }
  /**
   * @param certificateProfileId ID
   * @return true if the certificateId is matched by this search.
   */
  public boolean matchCp(final int certificateProfileId) {
    return cpIds.isEmpty()
        || cpIds.contains(Integer.valueOf(certificateProfileId));
  }
  /**
   * @param caId ID
   * @return true if the endEntityProfileId is matched by this search.
   */
  public boolean matchCa(final int caId) {
    return caIds.isEmpty() || caIds.contains(Integer.valueOf(caId));
  }

  /**
   * @param notBefore long
   * @return true if the notBefore is matched by this search.
   */
  public boolean matchIssuedInterval(final Long notBefore) {
    if (isIssuedAfterUsed()
        && (notBefore == null || notBefore.longValue() < issuedAfter)) {
      return false;
    }
    if (isIssuedBeforeUsed()
        && (notBefore == null || notBefore.longValue() > issuedBefore)) {
      return false;
    }
    return true;
  }

  /**
   * @param expireDate date
   * @return true if the expireDate is matched by this search.
   */
  public boolean matchExpiresInterval(final long expireDate) {
    if (isExpiresAfterUsed() && expireDate < expiresAfter) {
      return false;
    }
    if (isExpiresBeforeUsed() && expireDate > expiresBefore) {
      return false;
    }
    return true;
  }

  /**
   * @param revocationDate date
   * @return true if the expireDate is matched by this search.
   */
  public boolean matchRevokedInterval(final long revocationDate) {
    if (isRevokedAfterUsed() && revocationDate < revokedAfter) {
      return false;
    }
    if (isRevokedBeforeUsed() && revocationDate > revokedBefore) {
      return false;
    }
    return true;
  }

  /**
   * @param serialNumber SN
   * @return true if the serialNumber is matched by this search (either as
   *     decimal or hexadecimal).
   */
  public boolean matchSerialNumber(final String serialNumber) {
    return serialNumber.equals(getSerialNumberSearchStringFromDec())
        || serialNumber.equals(getSerialNumberSearchStringFromHex());
  }

  /**
   * @param username User
   * @return true if the username is matched by this search.
   */
  public boolean matchUsername(final String username) {
    return username != null
        && ((!usernameSearchExact
                && username
                    .toUpperCase()
                    .contains(usernameSearchString.toUpperCase()))
            || (usernameSearchExact
                && username.equalsIgnoreCase(usernameSearchString)));
  }
  /**
   * @param subjectDn DN
   * @return true if the subjectDn is matched by this search.
   */
  public boolean matchSubjectDn(final String subjectDn) {
    return subjectDn != null
        && ((!subjectDnSearchExact
                && subjectDn
                    .toUpperCase()
                    .contains(subjectDnSearchString.toUpperCase()))
            || (subjectDnSearchExact
                && subjectDn.equalsIgnoreCase(subjectDnSearchString)));
  }
  /**
   * @param subjectAn An
   * @return true if the subjectAn is matched by this search.
   */
  public boolean matchSubjectAn(final String subjectAn) {
    return subjectAn != null
        && ((!subjectAnSearchExact && subjectAn.contains(subjectAnSearchString))
            || (subjectAnSearchExact
                && subjectAn.equals(subjectAnSearchString)));
  }

  /**
   * @param status status
   * @param revocationReason rev
   * @return true if the certicate status and revocation reason is matched by
   *     this search.
   */
  public boolean matchStatusAndReason(
      final int status, final int revocationReason) {
    if (!statuses.isEmpty() && !statuses.contains(status)) {
      return false;
    }
    if (!revocationReasons.isEmpty()
        && !revocationReasons.contains(revocationReason)) {
      return false;
    }
    return true;
  }
}
