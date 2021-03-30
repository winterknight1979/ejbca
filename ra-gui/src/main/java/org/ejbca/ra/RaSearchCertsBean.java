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
package org.ejbca.ra;

import java.io.Serializable;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TimeZone;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.component.UIComponent;
import javax.faces.component.html.HtmlOutputLabel;
import javax.faces.context.FacesContext;
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.model.SelectItem;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.util.EJBTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.era.RaCertificateSearchRequest;
import org.ejbca.core.model.era.RaCertificateSearchResponse;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.ra.RaCertificateDetails.Callbacks;

/**
 * Backing bean for Search Certificates page.
 *
 * @version $Id: RaSearchCertsBean.java 26524 2017-09-11 09:12:49Z bastianf $
 *     TODO: Use CDI beans
 */
@SuppressWarnings("deprecation")
@ManagedBean
@ViewScoped
public class RaSearchCertsBean implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Param. */
  private static final Logger LOG = Logger.getLogger(RaSearchCertsBean.class);

  /** Param. */
  @EJB private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

  /** Param. */
  @ManagedProperty(value = "#{raAuthenticationBean}")
  private RaAuthenticationBean raAuthenticationBean;

  /**
   * @param araAuthenticationBean bean
   */
  public void setRaAuthenticationBean(
      final RaAuthenticationBean araAuthenticationBean) {
    this.raAuthenticationBean = araAuthenticationBean;
  }

  /** Param. */
  @ManagedProperty(value = "#{raLocaleBean}")
  private RaLocaleBean raLocaleBean;
/**
 * @param araLocaleBean bean
 */
  public void setRaLocaleBean(final RaLocaleBean araLocaleBean) {
    this.raLocaleBean = araLocaleBean;
  }

  /** Param. */
  private final List<RaCertificateDetails> resultsFiltered = new ArrayList<>();
  /** Param. */
  private Map<Integer, String> eepIdToNameMap = null;
  /** Param. */
  private Map<Integer, String> cpIdToNameMap = null;
  /** Param. */
  private final Map<String, String> caSubjectToNameMap = new HashMap<>();
  /** Param. */
  private final List<SelectItem> availableEeps = new ArrayList<>();
  /** Param. */
  private final List<SelectItem> availableCps = new ArrayList<>();
  /** Param. */
  private final List<SelectItem> availableCas = new ArrayList<>();

  /** Param. */
  private RaCertificateSearchRequest stagedRequest =
      new RaCertificateSearchRequest();
  /** Param. */
  private RaCertificateSearchRequest lastExecutedRequest = null;
  /** Param. */
  private RaCertificateSearchResponse lastExecutedResponse = null;

  /** Param. */
  private String genericSearchString = "";

  /** Param. */
  private String issuedAfter = "";
  /** Param. */
  private String issuedBefore = "";
  /** Param. */
  private String expiresAfter = "";
  /** Param. */
  private String expiresBefore = "";
  /** Param. */
  private String revokedAfter = "";
  /** Param. */
  private String revokedBefore = "";

  /** Param. */
  private UIComponent confirmPasswordComponent;

  private enum SortOrder {
      /** Param. */
    PROFILE,
    /** Param. */
    CA,
    /** Param. */
    SERIALNUMBER,
    /** Param. */
    SUBJECT,
    /** Param. */
    USERNAME,
    /** Param. */
    ISSUANCE,
    /** Param. */
    EXPIRATION,
    /** Param. */
    STATUS
  };

  /** Param. */
  private SortOrder sortBy = SortOrder.USERNAME;
  /** Param. */
  private boolean sortAscending = true;

  /** Param. */
  private boolean moreOptions = false;

  /** Param. */
  private RaCertificateDetails currentCertificateDetails = null;

  /** Callbacks. */
  private final Callbacks raCertificateDetailsCallbacks =
      new RaCertificateDetails.Callbacks() {
        @Override
        public RaLocaleBean getRaLocaleBean() {
          return raLocaleBean;
        }

        @Override
        public UIComponent getConfirmPasswordComponent() {
          return confirmPasswordComponent;
        }

        @Override
        public boolean changeStatus(
            final RaCertificateDetails raCertificateDetails,
            final int newStatus,
            final int newRevocationReason)
            throws ApprovalException, WaitingForApprovalException {
          final boolean ret =
              raMasterApiProxyBean.changeCertificateStatus(
                  raAuthenticationBean.getAuthenticationToken(),
                  raCertificateDetails.getFingerprint(),
                  newStatus,
                  newRevocationReason);
          if (ret) {
            // Re-initialize object if status has changed
            final CertificateDataWrapper cdw =
                raMasterApiProxyBean.searchForCertificate(
                    raAuthenticationBean.getAuthenticationToken(),
                    raCertificateDetails.getFingerprint());
            raCertificateDetails.reInitialize(
                cdw, cpIdToNameMap, eepIdToNameMap, caSubjectToNameMap);
          }
          return ret;
        }

        @Override
        public boolean recoverKey(
            final RaCertificateDetails raCertificateDetails)
            throws ApprovalException, CADoesntExistsException,
                AuthorizationDeniedException, WaitingForApprovalException,
                NoSuchEndEntityException, EndEntityProfileValidationException {
          final boolean ret =
              raMasterApiProxyBean.markForRecovery(
                  raAuthenticationBean.getAuthenticationToken(),
                  raCertificateDetails.getUsername(),
                  raCertificateDetails.getPassword(),
                  EJBTools.wrap(raCertificateDetails.getCertificate()),
                  false);
          return ret;
        }

        @Override
        public boolean keyRecoveryPossible(
            final RaCertificateDetails raCertificateDetails) {
          final boolean ret =
              raMasterApiProxyBean.keyRecoveryPossible(
                  raAuthenticationBean.getAuthenticationToken(),
                  raCertificateDetails.getCertificate(),
                  raCertificateDetails.getUsername());
          return ret;
        }
      };

  /** Invoked when the page is loaded. */
  public void initialize() {
    // Perform a search if parameters where passed in the query string
    if (genericSearchString != null) {
      searchAndFilterCommon();
    }
  }

  /** Invoked action on search form post. */
  public void searchAndFilterAction() {
    searchAndFilterCommon();
  }

  /**
   * Invoked on criteria changes.
   *
   * @param event Event
   */
  public void searchAndFilterAjaxListener(final AjaxBehaviorEvent event) {
    searchAndFilterCommon();
  }

  /**
   * Determine if we need to query back end or just filter and execute the
   * required action.
   */
  private void searchAndFilterCommon() {
    final int compared = stagedRequest.compareTo(lastExecutedRequest);
    boolean search = compared > 0;
    if (compared != 0) {
      stagedRequest.setPageNumber(0);
    }
    if (compared <= 0 && lastExecutedResponse != null) {
      // More narrow search → filter and check if there are sufficient results
      // left
      if (LOG.isDebugEnabled()) {
        LOG.debug("More narrow criteria → Filter");
      }
      filterTransformSort();
      // Check if there are sufficient results to fill screen and search for
      // more
      if (resultsFiltered.size() < lastExecutedRequest.getMaxResults()
          && lastExecutedResponse.isMightHaveMoreResults()) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Trying to load more results since filter left too few results →"
                  + " Query");
        }
        search = true;
      } else {
        search = false;
      }
    }
    if (search) {
      // Wider search → Query back-end
      if (LOG.isDebugEnabled()) {
        LOG.debug("Wider criteria → Query");
      }
      searchForCertificates();
    }
  }

  private void searchForCertificates() {
    lastExecutedResponse =
        raMasterApiProxyBean.searchForCertificates(
            raAuthenticationBean.getAuthenticationToken(), stagedRequest);
    if (!lastExecutedResponse.isMightHaveMoreResults()
        || !lastExecutedResponse.getCdws().isEmpty()) {
      // Only update last executed request when there is no timeout
      lastExecutedRequest = stagedRequest;
      stagedRequest = new RaCertificateSearchRequest(stagedRequest);
      filterTransformSort();
    }
  }

  /**
   * Perform in memory filtering using the current search criteria of the last
   * result set from the back end.
   */
  private void filterTransformSort() {
    resultsFiltered.clear();
    if (eepIdToNameMap == null
        || cpIdToNameMap == null
        || caSubjectToNameMap == null) {
      // If the session has been discontinued we need to ensure that we
      // repopulate the objects
      getAvailableEeps();
      getAvailableCps();
      getAvailableCas();
    }
    if (lastExecutedResponse != null) {
      for (final CertificateDataWrapper cdw : lastExecutedResponse.getCdws()) {
        // ...we don't filter if the requested maxResults is lower than the
        // search request
        if (!genericSearchString.isEmpty()
            && (!stagedRequest.matchSerialNumber(
                    cdw.getCertificateData().getSerialNumber())
                && !stagedRequest.matchUsername(
                    cdw.getCertificateData().getUsername())
                && !stagedRequest.matchSubjectDn(
                    cdw.getCertificateData().getSubjectDnNeverNull())
                && !stagedRequest.matchSubjectAn(
                    cdw.getCertificateData().getSubjectAltNameNeverNull()))) {
          continue;
        }
        if (!stagedRequest.matchEep(
            cdw.getCertificateData().getEndEntityProfileIdOrZero())) {
          continue;
        }
        if (!stagedRequest.matchCp(
            cdw.getCertificateData().getCertificateProfileId())) {
          continue;
        }
        if (!stagedRequest.matchCa(
            cdw.getCertificateData().getIssuerDN().hashCode())) {
          continue;
        }
        if (!stagedRequest.matchIssuedInterval(
            cdw.getCertificateData().getNotBefore())) {
          continue;
        }
        if (!stagedRequest.matchExpiresInterval(
            cdw.getCertificateData().getExpireDate())) {
          continue;
        }
        if (!stagedRequest.matchRevokedInterval(
            cdw.getCertificateData().getRevocationDate())) {
          continue;
        }
        if (!stagedRequest.matchStatusAndReason(
            cdw.getCertificateData().getStatus(),
            cdw.getCertificateData().getRevocationReason())) {
          continue;
        }
        resultsFiltered.add(
            new RaCertificateDetails(
                cdw,
                raCertificateDetailsCallbacks,
                cpIdToNameMap,
                eepIdToNameMap,
                caSubjectToNameMap));
      }
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Filtered "
                + lastExecutedResponse.getCdws().size()
                + " responses down to "
                + resultsFiltered.size()
                + " results.");
      }
      sort();
      chain();
    }
  }

  /** Sort the filtered result set based on the select column and sort order. */
  private void sort() {
    Collections.sort(
        resultsFiltered,
        new Comparator<RaCertificateDetails>() {
          @Override
          public int compare(
              final RaCertificateDetails o1, final RaCertificateDetails o2) {
            switch (sortBy) {
              case PROFILE:
                return o1.getEepName()
                        .concat(o1.getCpName())
                        .compareTo(o2.getEepName().concat(o2.getCpName()))
                    * (sortAscending ? 1 : -1);
              case CA:
                return o1.getCaName().compareTo(o2.getCaName())
                    * (sortAscending ? 1 : -1);
              case SERIALNUMBER:
                return o1.getSerialnumber().compareTo(o2.getSerialnumber())
                    * (sortAscending ? 1 : -1);
              case SUBJECT:
                return (o1.getSubjectDn() + o1.getSubjectAn())
                        .compareTo(o2.getSubjectDn() + o2.getSubjectAn())
                    * (sortAscending ? 1 : -1);
              case ISSUANCE:
                return o1.getCreated().compareTo(o2.getCreated())
                    * (sortAscending ? 1 : -1);
              case EXPIRATION:
                return o1.getExpires().compareTo(o2.getExpires())
                    * (sortAscending ? 1 : -1);
              case STATUS:
                return o1.getStatus().compareTo(o2.getStatus())
                    * (sortAscending ? 1 : -1);
              case USERNAME:
              default:
                return o1.getUsername().compareTo(o2.getUsername())
                    * (sortAscending ? 1 : -1);
            }
          }
        });
  }

  /**
   * @return true if there were no matching search results for the current
   *     criteria.
   */
  public boolean isResultsNone() {
    return getFilteredResults().isEmpty() && !isMoreResultsAvailable();
  }
  /**
   * @return true if there might be more search results for the current criteria
   *     than shown here.
   */
  public boolean isResultsMoreAvailable() {
    return !getFilteredResults().isEmpty() && isMoreResultsAvailable();
  }
  /**
   * @return true if there more search results for the given criteria, but there
   *     are no result which we assume is caused by a search or peer timeout.
   */
  public boolean isResultsTimeout() {
    return getFilteredResults().isEmpty() && isMoreResultsAvailable();
  }


  /**
   * @return sorted
   */
  public String getSortedByProfile() {
    return getSortedBy(SortOrder.PROFILE);
  }


  /** Sort. */
  public void sortByProfile() {
    sortBy(SortOrder.PROFILE, true);
  }


  /**
   * @return sorted
   */
  public String getSortedByCa() {
    return getSortedBy(SortOrder.CA);
  }


  /** Sort. */
  public void sortByCa() {
    sortBy(SortOrder.CA, true);
  }


  /**
   * @return sorted
   */
  public String getSortedBySerialNumber() {
    return getSortedBy(SortOrder.SERIALNUMBER);
  }


  /** Sort. */
  public void sortBySerialNumber() {
    sortBy(SortOrder.SERIALNUMBER, true);
  }


  /**
   * @return sorted
   */
  public String getSortedBySubject() {
    return getSortedBy(SortOrder.SUBJECT);
  }


  /** Sort. */
  public void sortBySubject() {
    sortBy(SortOrder.SUBJECT, true);
  }


  /**
   * @return sorted
   */
  public String getSortedByIssuance() {
    return getSortedBy(SortOrder.ISSUANCE);
  }


  /** Sort. */
  public void sortByIssuance() {
    sortBy(SortOrder.ISSUANCE, false);
  }


  /**
   * @return sorted
   */
  public String getSortedByExpiration() {
    return getSortedBy(SortOrder.EXPIRATION);
  }


  /** Sort. */
  public void sortByExpiration() {
    sortBy(SortOrder.EXPIRATION, false);
  }

  /**
   * @return sorted
   */
  public String getSortedByStatus() {
    return getSortedBy(SortOrder.STATUS);
  }


  /** Sort. */
  public void sortByStatus() {
    sortBy(SortOrder.STATUS, true);
  }

  /**
   * @return sorted
   */
  public String getSortedByUsername() {
    return getSortedBy(SortOrder.USERNAME);
  }

  /** Sort. */
  public void sortByUsername() {
    sortBy(SortOrder.USERNAME, true);
  }

  /**
   * @param sortOrder Order
   * @return an up or down arrow character depending on sort order if the sort
   *     column matches
   */
  private String getSortedBy(final SortOrder sortOrder) {
    if (sortBy.equals(sortOrder)) {
      return sortAscending ? "\u25bc" : "\u25b2";
    }
    return "";
  }
  /**
   * Set current sort column. Flip the order if the column was already selected.
   *
   * @param sortOrder Order
   * @param defaultAscending Order
   */
  private void sortBy(
      final SortOrder sortOrder, final boolean defaultAscending) {
    if (sortBy.equals(sortOrder)) {
      sortAscending = !sortAscending;
    } else {
      sortAscending = defaultAscending;
    }
    this.sortBy = sortOrder;
    sort();
  }

  /**
   * @return true if there might be more results in the back end than retrieved
   *     based on the current criteria.
   */
  public boolean isMoreResultsAvailable() {
    return lastExecutedResponse != null
        && lastExecutedResponse.isMightHaveMoreResults();
  }

  /**
   * @return true of more search criteria than just the basics should be shown
   */
  public boolean isMoreOptions() {
    return moreOptions;
  }

  /** Invoked when more or less options action is invoked. */
  public void moreOptionsAction() {
    moreOptions = !moreOptions;
    // Reset any criteria in the advanced section
    stagedRequest.resetMaxResults();
    stagedRequest.resetIssuedAfter();
    stagedRequest.resetIssuedBefore();
    stagedRequest.resetExpiresAfter();
    stagedRequest.resetExpiresBefore();
    stagedRequest.resetRevokedAfter();
    stagedRequest.resetRevokedBefore();
    issuedAfter = "";
    issuedBefore = "";
    expiresAfter = "";
    expiresBefore = "";
    revokedAfter = "";
    revokedBefore = "";
    searchAndFilterCommon();
  }

  /**
   * @return results
   */
  public List<RaCertificateDetails> getFilteredResults() {
    return resultsFiltered;
  }

  /**
   * @return search
   */
  public String getGenericSearchString() {
    return this.genericSearchString;
  }

  /**
   * @param agenericSearchString search
   */
  public void setGenericSearchString(final String agenericSearchString) {
    this.genericSearchString = agenericSearchString;
    stagedRequest.setSubjectDnSearchString(agenericSearchString);
    stagedRequest.setSubjectAnSearchString(agenericSearchString);
    stagedRequest.setUsernameSearchString(agenericSearchString);
    stagedRequest.setSerialNumberSearchStringFromDec(agenericSearchString);
    stagedRequest.setSerialNumberSearchStringFromHex(agenericSearchString);
  }

  /**
   * @return max
   */
  public int getCriteriaMaxResults() {
    return stagedRequest.getMaxResults();
  }

  /**
   * @param criteriaMaxResults max
   */
  public void setCriteriaMaxResults(final int criteriaMaxResults) {
    stagedRequest.setMaxResults(criteriaMaxResults);
  }

  /**
   * @return max
   */
  public List<SelectItem> getAvailableMaxResults() {
    List<SelectItem> ret = new ArrayList<>();
    for (final int value
       : new int[] {
          RaCertificateSearchRequest.DEFAULT_MAX_RESULTS, 50, 100, 200, 400
        }) {
      ret.add(
          new SelectItem(
              value,
              raLocaleBean.getMessage(
                  "search_certs_page_criteria_results_option", value)));
    }
    return ret;
  }

  /**
   * @return ID
   */
  public int getCriteriaEepId() {
    return stagedRequest.getEepIds().isEmpty()
        ? 0
        : stagedRequest.getEepIds().get(0);
  }

  /**
   * @param criteriaEepId ID
   */
  public void setCriteriaEepId(final int criteriaEepId) {
    if (criteriaEepId == 0) {
      stagedRequest.setEepIds(new ArrayList<Integer>());
    } else {
      stagedRequest.setEepIds(
          new ArrayList<>(Arrays.asList(new Integer[] {criteriaEepId})));
    }
  }

  /**
   * @return bool
   */
  public boolean isOnlyOneEepAvailable() {
    return getAvailableEeps().size() == 1;
  }

  /**
   * @return EEps
   */
  public List<SelectItem> getAvailableEeps() {
    if (availableEeps.isEmpty()) {
      eepIdToNameMap =
          raMasterApiProxyBean.getAuthorizedEndEntityProfileIdsToNameMap(
              raAuthenticationBean.getAuthenticationToken());
      availableEeps.add(
          new SelectItem(
              0,
              raLocaleBean.getMessage(
                  "search_certs_page_criteria_eep_optionany")));
      for (final Entry<Integer, String> entry
          : getAsSortedByValue(eepIdToNameMap.entrySet())) {
        availableEeps.add(
            new SelectItem(entry.getKey(), "- " + entry.getValue()));
      }
    }
    return availableEeps;
  }

  /**
   * @return ID
   */
  public int getCriteriaCpId() {
    return stagedRequest.getCpIds().isEmpty()
        ? 0
        : stagedRequest.getCpIds().get(0);
  }

  /**
   * @param criteriaCpId ID
   */
  public void setCriteriaCpId(final int criteriaCpId) {
    if (criteriaCpId == 0) {
      stagedRequest.setCpIds(new ArrayList<Integer>());
    } else {
      stagedRequest.setCpIds(
          new ArrayList<>(Arrays.asList(new Integer[] {criteriaCpId})));
    }
  }

  /**
   * @return bool
   */
  public boolean isOnlyOneCpAvailable() {
    return getAvailableCps().size() == 1;
  }

  /**
   * @return list
   */
  public List<SelectItem> getAvailableCps() {
    if (availableCps.isEmpty()) {
      cpIdToNameMap =
          raMasterApiProxyBean.getAuthorizedCertificateProfileIdsToNameMap(
              raAuthenticationBean.getAuthenticationToken());
      availableCps.add(
          new SelectItem(
              0,
              raLocaleBean.getMessage(
                  "search_certs_page_criteria_cp_optionany")));
      for (final Entry<Integer, String> entry
          : getAsSortedByValue(cpIdToNameMap.entrySet())) {
        availableCps.add(
            new SelectItem(entry.getKey(), "- " + entry.getValue()));
      }
    }
    return availableCps;
  }

  /**
   * @return ID
   */
  public int getCriteriaCaId() {
    return stagedRequest.getCaIds().isEmpty()
        ? 0
        : stagedRequest.getCaIds().get(0);
  }

  /**
   * @param criteriaCaId ID
   */
  public void setCriteriaCaId(final int criteriaCaId) {
    if (criteriaCaId == 0) {
      stagedRequest.setCaIds(new ArrayList<Integer>());
    } else {
      stagedRequest.setCaIds(
          new ArrayList<>(Arrays.asList(new Integer[] {criteriaCaId})));
    }
  }

  /**
   * @return bool
   */
  public boolean isOnlyOneCaAvailable() {
    return getAvailableCas().size() == 1;
  }

  /**
   * @return list
   */
  public List<SelectItem> getAvailableCas() {
    if (availableCas.isEmpty()) {
      final List<CAInfo> caInfos =
          new ArrayList<>(
              raMasterApiProxyBean.getAuthorizedCas(
                  raAuthenticationBean.getAuthenticationToken()));
      Collections.sort(
          caInfos,
          new Comparator<CAInfo>() {
            @Override
            public int compare(final CAInfo caInfo1, final CAInfo caInfo2) {
              return caInfo1.getName().compareTo(caInfo2.getName());
            }
          });
      for (final CAInfo caInfo : caInfos) {
        caSubjectToNameMap.put(caInfo.getSubjectDN(), caInfo.getName());
      }
      availableCas.add(
          new SelectItem(
              0,
              raLocaleBean.getMessage(
                  "search_certs_page_criteria_ca_optionany")));
      for (final CAInfo caInfo : caInfos) {
        availableCas.add(
            new SelectItem(caInfo.getCAId(), "- " + caInfo.getName()));
      }
    }
    return availableCas;
  }

  /**
   * @return bool
   */
  public boolean isShowNextPageButton() {
    return lastExecutedResponse != null
        && lastExecutedResponse.isMightHaveMoreResults();
  }

  /**
   * @return bool
   */
  public boolean isShowPreviousPageButton() {
    return stagedRequest != null && stagedRequest.getPageNumber() > 0;
  }

  /**
   * @return date
   */
  public String getIssuedAfter() {
    return getDateAsString(issuedAfter, stagedRequest.getIssuedAfter(), 0L);
  }

  /**
   * @param anissuedAfter date
   */
  public void setIssuedAfter(final String anissuedAfter) {
    this.issuedAfter = anissuedAfter;
    stagedRequest.setIssuedAfter(
            parseDateAndUseDefaultOnFail(anissuedAfter, 0L));
  }

  /**
   * @return date
   */
  public String getIssuedBefore() {
    return getDateAsString(
        issuedBefore, stagedRequest.getIssuedBefore(), Long.MAX_VALUE);
  }

  /**
   * @param anissuedBefore issued
   */
  public void setIssuedBefore(final String anissuedBefore) {
    this.issuedBefore = anissuedBefore;
    stagedRequest.setIssuedBefore(
        parseDateAndUseDefaultOnFail(anissuedBefore, Long.MAX_VALUE));
  }

  /**
   * @return date
   */
  public String getExpiresAfter() {
    return getDateAsString(expiresAfter, stagedRequest.getExpiresAfter(), 0L);
  }

  /**
   * @param anexpiresAfter date
   */
  public void setExpiresAfter(final String anexpiresAfter) {
    this.expiresAfter = anexpiresAfter;
    stagedRequest.setExpiresAfter(
        parseDateAndUseDefaultOnFail(anexpiresAfter, 0L));
  }

  /**
   * @return date
   */
  public String getExpiresBefore() {
    return getDateAsString(
        expiresBefore, stagedRequest.getExpiresBefore(), Long.MAX_VALUE);
  }

  /**
   * @param anexpiresBefore date
   */
  public void setExpiresBefore(final String anexpiresBefore) {
    this.expiresBefore = anexpiresBefore;
    stagedRequest.setExpiresBefore(
        parseDateAndUseDefaultOnFail(anexpiresBefore, Long.MAX_VALUE));
  }

  /**
   * @return dtae
   */
  public String getRevokedAfter() {
    return getDateAsString(revokedAfter, stagedRequest.getRevokedAfter(), 0L);
  }

  /**
   * @param arevokedAfter date
   */
  public void setRevokedAfter(final String arevokedAfter) {
    this.revokedAfter = arevokedAfter;
    stagedRequest.setRevokedAfter(
        parseDateAndUseDefaultOnFail(arevokedAfter, 0L));
  }

  /**
   * @return Date
   */
  public String getRevokedBefore() {
    return getDateAsString(
        revokedBefore, stagedRequest.getRevokedBefore(), Long.MAX_VALUE);
  }

  /**
   * @param arevokedBefore date
   */
  public void setRevokedBefore(final String arevokedBefore) {
    this.revokedBefore = arevokedBefore;
    stagedRequest.setRevokedBefore(
        parseDateAndUseDefaultOnFail(arevokedBefore, Long.MAX_VALUE));
  }

  /**
   * Query for the next page of search results.
   *
   * @param event Event
   */
  public void queryNextPage(final AjaxBehaviorEvent event) {
    stagedRequest.setPageNumber(stagedRequest.getPageNumber() + 1);
    searchForCertificates();
  }

  /**
   * Query for the previous page of search results.
   *
   * @param event Event
   */
  public void queryPreviousPage(final AjaxBehaviorEvent event) {
    stagedRequest.setPageNumber(stagedRequest.getPageNumber() - 1);
    searchForCertificates();
  }

  /**
   * @param stagedValue Value
   * @param value Value
   * @param defaultValue Default
   * @return the current value if the staged request value if the default value
   */
  private String getDateAsString(
      final String stagedValue, final long value, final long defaultValue) {
    if (value == defaultValue) {
      return stagedValue;
    }
    return ValidityDate.formatAsISO8601ServerTZ(value, TimeZone.getDefault());
  }
  /**
   * @param input Input
   * @param defaultValue Value
   * @return the staged request value if it is a parsable date and the default
   *     value otherwise
   */
  private long parseDateAndUseDefaultOnFail(
      final String input, final long defaultValue) {
    markCurrentComponentAsValid(true);
    if (!input.trim().isEmpty()) {
      try {
        return ValidityDate.parseAsIso8601(input).getTime();
      } catch (ParseException e) {
        markCurrentComponentAsValid(false);
        raLocaleBean.addMessageWarn("search_certs_page_warn_invaliddate");
      }
    }
    return defaultValue;
  }

  /**
   * Set or remove the styleClass "invalidInput" on the label with a
   * for-attribute matching the current input component.
   *
   * @param valid Valid
   */
  private void markCurrentComponentAsValid(final boolean valid) {
    final String styleClassInvalid = "invalidInput";
    // UIComponent.getCurrentComponent only works when invoked via f:ajax
    final UIComponent uiComponent =
        UIComponent.getCurrentComponent(FacesContext.getCurrentInstance());
    final String id = uiComponent.getId();
    final List<UIComponent> siblings = uiComponent.getParent().getChildren();
    for (final UIComponent sibling : siblings) {
      if (sibling instanceof HtmlOutputLabel) {
        final HtmlOutputLabel htmlOutputLabel = (HtmlOutputLabel) sibling;
        if (htmlOutputLabel.getFor().equals(id)) {
          String styleClass = htmlOutputLabel.getStyleClass();
          if (valid) {
            if (styleClass != null
                && styleClass.contains(styleClassInvalid)) {
              styleClass = styleClass.replace(styleClassInvalid, "").trim();
            }
          } else {
            if (styleClass == null) {
              styleClass = styleClassInvalid;
            } else {
              if (!styleClass.contains(styleClassInvalid)) {
                styleClass = styleClass.concat(" " + styleClassInvalid);
              }
            }
          }
          htmlOutputLabel.setStyleClass(styleClass);
        }
      }
    }
  }

  /**
   * @return Status
   */
  public String getCriteriaStatus() {
    final StringBuilder sb = new StringBuilder();
    final List<Integer> statuses = stagedRequest.getStatuses();
    final List<Integer> revocationReasons =
        stagedRequest.getRevocationReasons();
    if (statuses.contains(CertificateConstants.CERT_ACTIVE)) {
      sb.append(CertificateConstants.CERT_ACTIVE);
    } else if (statuses.contains(CertificateConstants.CERT_REVOKED)) {
      sb.append(CertificateConstants.CERT_REVOKED);
      if (!revocationReasons.isEmpty()) {
        sb.append("_").append(revocationReasons.get(0));
      }
    }
    return sb.toString();
  }

  /**
   * @param criteriaStatus Status
   */
  public void setCriteriaStatus(final String criteriaStatus) {
    final List<Integer> statuses = new ArrayList<>();
    final List<Integer> revocationReasons = new ArrayList<>();
    if (criteriaStatus != null && !criteriaStatus.isEmpty()) {
      final String[] criteriaStatusSplit = criteriaStatus.split("_");
      if (String.valueOf(CertificateConstants.CERT_ACTIVE)
          .equals(criteriaStatusSplit[0])) {
        statuses.addAll(
            Arrays.asList(
                new Integer[] {
                  CertificateConstants.CERT_ACTIVE,
                  CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION
                }));
      } else {
        statuses.addAll(
            Arrays.asList(
                new Integer[] {
                  CertificateConstants.CERT_REVOKED,
                  CertificateConstants.CERT_ARCHIVED
                }));
        if (criteriaStatusSplit.length > 1) {
          revocationReasons.addAll(
              Arrays.asList(
                  new Integer[] {Integer.parseInt(criteriaStatusSplit[1])}));
        }
      }
    }
    stagedRequest.setStatuses(statuses);
    stagedRequest.setRevocationReasons(revocationReasons);
  }

  /**
   * @return List
   */
  public List<SelectItem> getAvailableStatuses() {
    final List<SelectItem> ret = new ArrayList<>();
    ret.add(
        new SelectItem(
            "",
            raLocaleBean.getMessage(
                "search_certs_page_criteria_status_option_any")));
    ret.add(
        new SelectItem(
            String.valueOf(CertificateConstants.CERT_ACTIVE),
            raLocaleBean.getMessage(
                "search_certs_page_criteria_status_option_active")));
    ret.add(
        new SelectItem(
            String.valueOf(CertificateConstants.CERT_REVOKED),
            raLocaleBean.getMessage(
                "search_certs_page_criteria_status_option_revoked")));
    ret.add(
        getAvailableStatusRevoked(
            RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED));
    ret.add(
        getAvailableStatusRevoked(
            RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE));
    ret.add(
        getAvailableStatusRevoked(
            RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE));
    ret.add(
        getAvailableStatusRevoked(
            RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED));
    ret.add(
        getAvailableStatusRevoked(
            RevokedCertInfo.REVOCATION_REASON_SUPERSEDED));
    ret.add(
        getAvailableStatusRevoked(
            RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION));
    ret.add(
        getAvailableStatusRevoked(
            RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD));
    ret.add(
        getAvailableStatusRevoked(
            RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL));
    ret.add(
        getAvailableStatusRevoked(
            RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN));
    ret.add(
        getAvailableStatusRevoked(
            RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE));
    return ret;
  }

  private SelectItem getAvailableStatusRevoked(final int reason) {
    return new SelectItem(
        CertificateConstants.CERT_REVOKED + "_" + reason,
        raLocaleBean.getMessage(
            "search_certs_page_criteria_status_option_revoked_reason_"
                + reason));
  }

  private <T> List<Entry<T, String>> getAsSortedByValue(
      final Set<Entry<T, String>> entrySet) {
    final List<Entry<T, String>> entrySetSorted = new ArrayList<>(entrySet);
    Collections.sort(
        entrySetSorted,
        new Comparator<Entry<T, String>>() {
          @Override
          public int compare(
              final Entry<T, String> o1, final Entry<T, String> o2) {
            return o1.getValue().compareTo(o2.getValue());
          }
        });
    return entrySetSorted;
  }

  /**
   * @return UI
   */
  public UIComponent getConfirmPasswordComponent() {
    return confirmPasswordComponent;
  }

  /**
   * @param aconfirmPasswordComponent UI
   */
  public void setConfirmPasswordComponent(
      final UIComponent aconfirmPasswordComponent) {
    this.confirmPasswordComponent = aconfirmPasswordComponent;
  }

  /**
   * Chain the results in the current order for certificate details navigation.
   */
  private void chain() {
    RaCertificateDetails previous = null;
    for (final RaCertificateDetails current : resultsFiltered) {
      current.setPrevious(previous);
      if (previous != null) {
        previous.setNext(current);
      }
      previous = current;
    }
    if (!resultsFiltered.isEmpty()) {
      resultsFiltered.get(resultsFiltered.size() - 1).setNext(null);
    }
  }

  /**
   * @param selected Cert
   */
  public void openCertificateDetails(final RaCertificateDetails selected) {
    currentCertificateDetails = selected;
  }

  /**
   * @return cert
   */
  public RaCertificateDetails getCurrentCertificateDetails() {
    return currentCertificateDetails;
  }

  /** Next. */
  public void nextCertificateDetails() {
    currentCertificateDetails = currentCertificateDetails.getNext();
  }

  /** Prev. */
  public void previousCertificateDetails() {
    currentCertificateDetails = currentCertificateDetails.getPrevious();
  }

  /**
   * Close.
   */
  public void closeCertificateDetails() {
    currentCertificateDetails = null;
  }
}
