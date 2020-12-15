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
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang.builder.HashCodeBuilder;

/**
 * Search request for end entities from RA UI.
 *
 * @version $Id: RaEndEntitySearchRequest.java 26524 2017-09-11 09:12:49Z
 *     bastianf $
 */
public class RaEndEntitySearchRequest
    implements Serializable, Comparable<RaEndEntitySearchRequest> {

  private static final long serialVersionUID = 1L;
  // private static final Logger log =
  // Logger.getLogger(RaEndEntitySearchRequest.class);
  /** Param. */
  public static final int DEFAULT_MAX_RESULTS = 25;

  /** Param. */
  private int maxResults = DEFAULT_MAX_RESULTS;
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
  private long modifiedAfter = 0L;
  /** Param. */
  private long modifiedBefore = Long.MAX_VALUE;
  /** Param. */
  private List<Integer> statuses = new ArrayList<>();
  /** Param. */
  private int pageNumber = 0;

  /** Default constructor. */
  public RaEndEntitySearchRequest() { }

  /**
   * Copy constructor.
   *
   * @param request req
   */
  public RaEndEntitySearchRequest(final RaEndEntitySearchRequest request) {
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
    modifiedAfter = request.modifiedAfter;
    modifiedBefore = request.modifiedBefore;
    statuses.addAll(request.statuses);
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
   * @param amaxResults max
   */
  public void setMaxResults(final int amaxResults) {
    this.maxResults = amaxResults;
  }

  /**
   * @return IDs
   */
  public List<Integer> getEepIds() {
    return eepIds;
  }

  /**
   * @param theeepIds IDs
   */
  public void setEepIds(final List<Integer> theeepIds) {
    this.eepIds = theeepIds;
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
   * @return Search
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
   * @return String
   */
  public String getUsernameSearchString() {
    return usernameSearchString;
  }

  /**
   * @param ausernameSearchString String
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
   * @return long
   */
  public long getModifiedAfter() {
    return modifiedAfter;
  }

  /**
   * @param amodifiedAfter long
   */
  public void setModifiedAfter(final long amodifiedAfter) {
    this.modifiedAfter = amodifiedAfter;
  }

  /**
   * @return Bool
   */
  public boolean isModifiedAfterUsed() {
    return modifiedAfter > 0L;
  }

  /** Reset.
   */
  public void resetModifiedAfter() {
    this.modifiedAfter = 0L;
  }

  /**
   * @return long
   */
  public long getModifiedBefore() {
    return modifiedBefore;
  }

  /**
   * @param amodifiedBefore long
   */
  public void setModifiedBefore(final long amodifiedBefore) {
    this.modifiedBefore = amodifiedBefore;
  }

  /**
   * @return bool
   */
  public boolean isModifiedBeforeUsed() {
    return modifiedBefore < Long.MAX_VALUE;
  }

  /** Reset.
   */
  public void resetModifiedBefore() {
    this.modifiedBefore = Long.MAX_VALUE;
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

  @Override
  public int hashCode() {
    return HashCodeBuilder.reflectionHashCode(this);
  }

  @Override
  public boolean equals(final Object object) {
    if (!(object instanceof RaEndEntitySearchRequest)) {
      return false;
    }
    final RaEndEntitySearchRequest request = (RaEndEntitySearchRequest) object;
    return compareTo(request) == 0
        && this.pageNumber == request.getPageNumber();
  }

  // negative = this object is less (more narrow) than other. E.g. only when
  // other contains this and more.
  // positive = this object is greater (wider) than other
  // zero = this object is equal to other
  @Override
  public int compareTo(final RaEndEntitySearchRequest other) {
    if (other == null) {
      return 1;
    }
    // First check if there is any there is any indication that this does not
    // contain the whole other
    if (maxResults > other.maxResults
        || isWider(eepIds, other.eepIds)
        || isWider(cpIds, other.cpIds)
        || isWider(caIds, other.caIds)
        || modifiedAfter < other.modifiedAfter
        || modifiedBefore > other.modifiedBefore
        || isWider(subjectDnSearchString, other.subjectDnSearchString)
        || isWider(subjectDnSearchExact, other.subjectDnSearchExact)
        || isWider(subjectAnSearchString, other.subjectAnSearchString)
        || isWider(subjectAnSearchExact, other.subjectAnSearchExact)
        || isWider(usernameSearchString, other.usernameSearchString)
        || isWider(usernameSearchExact, other.usernameSearchExact)
        || isWider(statuses, other.statuses)) {
      // This does not contain whole other → wider
      return 1;
    }
    // Next check if this object is more narrow than the other
    if (maxResults < other.maxResults
        || isMoreNarrow(eepIds, other.eepIds)
        || isMoreNarrow(cpIds, other.cpIds)
        || isMoreNarrow(caIds, other.caIds)
        || modifiedAfter > other.modifiedAfter
        || modifiedBefore < other.modifiedBefore
        || isMoreNarrow(subjectDnSearchString, other.subjectDnSearchString)
        || isMoreNarrow(subjectDnSearchExact, other.subjectDnSearchExact)
        || isMoreNarrow(subjectAnSearchString, other.subjectAnSearchString)
        || isMoreNarrow(subjectAnSearchExact, other.subjectAnSearchExact)
        || isMoreNarrow(usernameSearchString, other.usernameSearchString)
        || isMoreNarrow(usernameSearchExact, other.usernameSearchExact)
        || isMoreNarrow(statuses, other.statuses)) {
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
   * @param otherObjectExact obj
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
   * @param modified mod
   * @return true if the notBefore is matched by this search.
   */
  public boolean matchModifiedInterval(final Long modified) {
    if (isModifiedAfterUsed()
        && (modified == null || modified.longValue() < modifiedAfter)) {
      return false;
    }
    if (isModifiedBeforeUsed()
        && (modified == null || modified.longValue() > modifiedBefore)) {
      return false;
    }
    return true;
  }

  /**
   * @param username user
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
   * @param status Status
   * @return true if the EE status is matched by this search.
   */
  public boolean matchStatus(final int status) {
    if (!statuses.isEmpty() && !statuses.contains(status)) {
      return false;
    }
    return true;
  }
}
