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
package org.ejbca.ui.web.admin.cainterface;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.NullCryptoToken;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/**
 * JSF Managed Bean or the CA Activation page of the Admin GUI.
 *
 * @version $Id: CAActivationMBean.java 28844 2018-05-04 08:31:02Z samuellb $
 */
public class CAActivationMBean extends BaseManagedBean implements Serializable {

    /** Log. */
  private static final Logger LOG = Logger.getLogger(CAActivationMBean.class);

  private static final long serialVersionUID = -2660384552215596717L;

  /** GUI representation of a CA for the activation view. */
  public final class CaActivationGuiInfo {
        /** Param. */
    private final int status;
    /** Param. */
    private final String name;
    /** Param. */
    private final int caId;
    /** Param. */
    private final boolean monitored;
    /** Param. */
    private boolean monitoredNewState;
    /** Param. */
    private boolean newState;

    private CaActivationGuiInfo(
        final int astatus,
        final boolean amonitored,
        final String aname,
        final int acaId) {
      this.status = astatus;
      this.newState = isActive();
      this.monitored = amonitored;
      this.monitoredNewState = amonitored;
      this.name = aname;
      this.caId = acaId;
    }

    /**
     * @return bool
     */
    public boolean isActive() {
      return status == CAConstants.CA_ACTIVE;
    }

    /**
     * @return bool
     */
    public boolean isExpired() {
      return status == CAConstants.CA_EXPIRED;
    }

    /**
     * @return bool
     */
    public boolean isRevoked() {
      return status == CAConstants.CA_REVOKED;
    }

    /**
     * @return bool
     */
    public boolean isExternal() {
      return status == CAConstants.CA_EXTERNAL;
    }

    /**
     * @return bool
     */
    public boolean isWaiting() {
      return status == CAConstants.CA_WAITING_CERTIFICATE_RESPONSE;
    }

    /**
     * @return bool
     */
    public boolean isUnableToChangeState() {
      return isRevoked() || isExpired() || isExternal() || isWaiting();
    }

    /**
     * @return bool
     */
    public boolean isOffline() {
      return !isActive() && !isExpired() && !isRevoked();
    }

    /**
     * @return bool
     */
    public boolean isMonitoredNewState() {
      return monitoredNewState;
    }

    /**
     * @param ismonitoredNewState bool
     */
    public void setMonitoredNewState(final boolean ismonitoredNewState) {
      this.monitoredNewState = ismonitoredNewState;
    }

    /**
     * @return bool
     */
    public boolean isMonitored() {
      return monitored;
    }

    /**
     * @return Status
     */
    public int getStatus() {
      return status;
    }

    /**
     * @return name
     */
    public String getName() {
      return name;
    }

    /**
     * @return ID
     */
    public int getCaId() {
      return caId;
    }

    /**
     * @return bool
     */
    public boolean isNewState() {
      return newState;
    }

    /**
     * @param anewState bool
     */
    public void setNewState(final boolean anewState) {
      this.newState = anewState;
    }
  }

  /**
   * GUI representation of a CryptoToken and its CA(s) for the activation view.
   */
  public class TokenAndCaActivationGuiInfo {
        /** Param. */
    private final CryptoTokenInfo cryptoTokenInfo;
    /** Param. */
    private final List<CaActivationGuiInfo> caActivationGuiInfos =
        new ArrayList<>();
    /** Param. */
    private final boolean allowedActivation;
    /** Param. */
    private final boolean allowedDeactivation;
    /** Param. */
    private boolean cryptoTokenNewState;

    private TokenAndCaActivationGuiInfo(
        final CryptoTokenInfo acryptoTokenInfo,
        final boolean isallowedActivation,
        final boolean isallowedDeactivation) {
      this.cryptoTokenInfo = acryptoTokenInfo;
      this.cryptoTokenNewState = acryptoTokenInfo.isActive();
      this.allowedActivation = isallowedActivation;
      this.allowedDeactivation = isallowedDeactivation;
    }

    /**
     * @param cryptoTokenId ID
     */
    public TokenAndCaActivationGuiInfo(final Integer cryptoTokenId) {
      this.cryptoTokenInfo =
          new CryptoTokenInfo(
              cryptoTokenId,
              "CryptoToken id " + cryptoTokenId,
              false,
              false,
              NullCryptoToken.class,
              new Properties());
      this.cryptoTokenNewState = false;
      this.allowedActivation = false;
      this.allowedDeactivation = false;
    }

    /**
     * @param caActivationGuiInfo info
     */
    public void add(final CaActivationGuiInfo caActivationGuiInfo) {
      caActivationGuiInfos.add(caActivationGuiInfo);
    }

    /**
     * @return CAS
     */
    public List<CaActivationGuiInfo> getCas() {
      return caActivationGuiInfos;
    }

    /**
     * @return ID
     */
    public int getCryptoTokenId() {
      return cryptoTokenInfo.getCryptoTokenId();
    }

    /**
     * @return name
     */
    public String getCryptoTokenName() {
      return cryptoTokenInfo.getName();
    }
    /**
     * @return bool
     */
    public boolean isExisting() {
      return !"NullCryptoToken".equals(cryptoTokenInfo.getType());
    }
    /**
     * @return bool
     */
    public boolean isCryptoTokenActive() {
      return cryptoTokenInfo.isActive();
    }
    /**
     * @return bool
     */
    public boolean isAutoActivated() {
      return cryptoTokenInfo.isAutoActivation();
    }

    /**
     * @return bool
     */
    public boolean isStateChangeDisabled() {
      return isAutoActivated()
          || (isCryptoTokenActive() && !allowedDeactivation)
          || (!isCryptoTokenActive() && !allowedActivation);
    }

    /**
     * @return state
     */
    public boolean isCryptoTokenNewState() {
      return cryptoTokenNewState;
    }

    /**
     * @param acryptoTokenNewState state
     */
    public void setCryptoTokenNewState(final boolean acryptoTokenNewState) {
      this.cryptoTokenNewState = acryptoTokenNewState;
    }
  }

  /**
   * GUI representation of a CryptoToken and its CA(s) for the activation view.
   */
  public class TokenAndCaActivationGuiComboInfo {
        /** Param. */
    private final boolean firstCryptoTokenListing;
    /** Param. */
    private final TokenAndCaActivationGuiInfo cryptoTokenInfo;
    /** Param. */
    private final CaActivationGuiInfo caActivationGuiInfo;

    /**
     * @param acryptoTokenInfo token
     * @param acaActivationGuiInfo CA
     * @param first bool
     */
    public TokenAndCaActivationGuiComboInfo(
        final TokenAndCaActivationGuiInfo acryptoTokenInfo,
        final CaActivationGuiInfo acaActivationGuiInfo,
        final boolean first) {
      this.cryptoTokenInfo = acryptoTokenInfo;
      this.caActivationGuiInfo = acaActivationGuiInfo;
      this.firstCryptoTokenListing = first;
    }

    /**
     * @return bool
     */
    public boolean isFirst() {
      return firstCryptoTokenListing;
    }

    /**
     * @return Token
     */
    public TokenAndCaActivationGuiInfo getCryptoToken() {
      return cryptoTokenInfo;
    }

    /**
     * @return CA
     */
    public CaActivationGuiInfo getCa() {
      return caActivationGuiInfo;
    }
  }

  /** Param. */
  private final AuthenticationToken authenticationToken =
      EjbcaJSFHelper.getBean().getEjbcaWebBean().getAdminObject();
  /** Param. */
  private final EjbLocalHelper ejbLocalhelper = new EjbLocalHelper();
  /** Param. */
  private final CAAdminSessionLocal caAdminSession =
      ejbLocalhelper.getCaAdminSession();
  /** Param. */
  private final CaSessionLocal caSession = ejbLocalhelper.getCaSession();
  /** Param. */
  private final CryptoTokenManagementSessionLocal cryptoTokenManagementSession =
      ejbLocalhelper.getCryptoTokenManagementSession();
  /** Param. */
  private final AuthorizationSessionLocal authorizationSession =
      ejbLocalhelper.getAuthorizationSession();

  /** Param. */
  private List<TokenAndCaActivationGuiComboInfo> authorizedTokensAndCas = null;
  /** Param. */
  private String authenticationcode;

  /**
   * @return info
   */
  public List<TokenAndCaActivationGuiComboInfo> getAuthorizedTokensAndCas() {
    final Map<Integer, TokenAndCaActivationGuiInfo> sortMap = new HashMap<>();
    for (final CAInfo caInfo
        : caSession.getAuthorizedAndEnabledCaInfos(authenticationToken)) {
      final Integer cryptoTokenId =
          Integer.valueOf(caInfo.getCAToken().getCryptoTokenId());
      if (sortMap.get(cryptoTokenId) == null) {
        // Perhaps not authorized to view the CryptoToken used by the CA, but we
        // implicitly
        // allow this in the current context since we are authorized to the CA.
        final CryptoTokenInfo cryptoTokenInfo =
            cryptoTokenManagementSession.getCryptoTokenInfo(
                cryptoTokenId.intValue());
        if (cryptoTokenInfo == null) {
          sortMap.put(
              cryptoTokenId, new TokenAndCaActivationGuiInfo(cryptoTokenId));
        } else {
          final boolean allowedActivation =
              authorizationSession.isAuthorizedNoLogging(
                  authenticationToken,
                  CryptoTokenRules.ACTIVATE.resource() + '/' + cryptoTokenId);
          final boolean allowedDeactivation =
              authorizationSession.isAuthorizedNoLogging(
                  authenticationToken,
                  CryptoTokenRules.DEACTIVATE.resource() + '/' + cryptoTokenId);
          sortMap.put(
              cryptoTokenId,
              new TokenAndCaActivationGuiInfo(
                  cryptoTokenInfo, allowedActivation, allowedDeactivation));
        }
      }
      sortMap
          .get(cryptoTokenId)
          .add(
              new CaActivationGuiInfo(
                  caInfo.getStatus(),
                  caInfo.getIncludeInHealthCheck(),
                  caInfo.getName(),
                  caInfo.getCAId()));
    }
    final TokenAndCaActivationGuiInfo[] tokenAndCasArray =
        sortMap.values().toArray(new TokenAndCaActivationGuiInfo[0]);
    // Sort array by CryptoToken name
    Arrays.sort(
        tokenAndCasArray,
        new Comparator<TokenAndCaActivationGuiInfo>() {
          @Override
          public int compare(
              final TokenAndCaActivationGuiInfo o1,
              final TokenAndCaActivationGuiInfo o2) {
            return o1.getCryptoTokenName()
                .compareToIgnoreCase(o2.getCryptoTokenName());
          }
        });
    final List<TokenAndCaActivationGuiComboInfo> retValues = new ArrayList<>();
    for (final TokenAndCaActivationGuiInfo value : tokenAndCasArray) {
      boolean first = true;
      final CaActivationGuiInfo[] casArray =
          value.getCas().toArray(new CaActivationGuiInfo[0]);
      // Sort array by CA name
      Arrays.sort(
          casArray,
          new Comparator<CaActivationGuiInfo>() {
            @Override
            public int compare(
                final CaActivationGuiInfo o1, final CaActivationGuiInfo o2) {
              return o1.getName().compareToIgnoreCase(o2.getName());
            }
          });
      for (final CaActivationGuiInfo value2 : casArray) {
        retValues.add(
            new TokenAndCaActivationGuiComboInfo(value, value2, first));
        first = false;
      }
    }
    authorizedTokensAndCas = retValues;
    return retValues;
  }

  /**
   * Tries to activate CryptoTokens (once for each), if authentication code is
   * present and activation is requested. Set the CA service status to the
   * requested state for each CA.
   */
  public void applyChanges() {
    if (authorizedTokensAndCas == null) {
      return;
    }
    for (final TokenAndCaActivationGuiComboInfo tokenAndCaCombo
        : authorizedTokensAndCas) {
      if (tokenAndCaCombo.isFirst()) {
        TokenAndCaActivationGuiInfo tokenAndCa =
            tokenAndCaCombo.getCryptoToken();
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "isCryptoTokenActive(): "
                  + tokenAndCa.isCryptoTokenActive()
                  + " isCryptoTokenNewState(): "
                  + tokenAndCa.isCryptoTokenNewState());
        }
        if (tokenAndCa.isCryptoTokenActive()
            != tokenAndCa.isCryptoTokenNewState()) {
          if (tokenAndCa.isCryptoTokenNewState()) {
            // Assert that authcode is present
            if (authenticationcode != null && authenticationcode.length() > 0) {
              // Activate CA's CryptoToken
              try {
                cryptoTokenManagementSession.activate(
                    authenticationToken,
                    tokenAndCa.getCryptoTokenId(),
                    authenticationcode.toCharArray());
                LOG.info(
                    authenticationToken.toString()
                        + " activated CryptoToken "
                        + tokenAndCa.getCryptoTokenId());
              } catch (CryptoTokenAuthenticationFailedException e) {
                super.addNonTranslatedErrorMessage("Bad authentication code.");
              } catch (CryptoTokenOfflineException e) {
                super.addNonTranslatedErrorMessage(
                    "Crypto Token is offline and cannot be activated.");
              } catch (AuthorizationDeniedException e) {
                super.addNonTranslatedErrorMessage(e.getMessage());
              }
            } else {
              super.addNonTranslatedErrorMessage(
                  "Authentication code required.");
            }
          } else {
            // Deactivate CA's CryptoToken
            try {
              cryptoTokenManagementSession.deactivate(
                  authenticationToken, tokenAndCa.getCryptoTokenId());
              LOG.info(
                  authenticationToken.toString()
                      + " deactivated CryptoToken "
                      + tokenAndCa.getCryptoTokenId());
            } catch (AuthorizationDeniedException e) {
              super.addNonTranslatedErrorMessage(e.getMessage());
            }
          }
        }
      }
      CaActivationGuiInfo ca = tokenAndCaCombo.getCa();
      if (ca.isActive() != ca.isNewState()) {
        // Valid transition 1: Currently offline, become active
        if (ca.isNewState() && ca.getStatus() == CAConstants.CA_OFFLINE) {
          try {
            caAdminSession.activateCAService(authenticationToken, ca.getCaId());
          } catch (Exception e) {
            super.addNonTranslatedErrorMessage(e.getMessage());
          }
        }
        // Valid transition 2: Currently online, become offline
        if (!ca.isNewState() && ca.getStatus() == CAConstants.CA_ACTIVE) {
          try {
            caAdminSession.deactivateCAService(
                authenticationToken, ca.getCaId());
          } catch (Exception e) {
            super.addNonTranslatedErrorMessage(e.getMessage());
          }
        }
      }
      if (ca.isMonitored() != ca.isMonitoredNewState()) {
        // Only persist changes if there are any
        try {
          final CAInfo caInfo =
              caSession.getCAInfoInternal(ca.getCaId(), null, false);
          caInfo.setIncludeInHealthCheck(ca.isMonitoredNewState());
          caAdminSession.editCA(authenticationToken, caInfo);
        } catch (AuthorizationDeniedException e) {
          super.addNonTranslatedErrorMessage(e.getMessage());
        }
      }
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "caId: "
                + ca.getCaId()
                + " monitored: "
                + ca.isMonitored()
                + " newCaStatus: "
                + ca.isNewState());
      }
    }
  }

  /**
   * @return true when there is at least one CryptoToken that can be activated.
   */
  public boolean isActivationCodeShown() {
    if (authorizedTokensAndCas != null) {
      for (final TokenAndCaActivationGuiComboInfo tokenAndCa
          : authorizedTokensAndCas) {
        if (tokenAndCa.isFirst()) {
          if (!tokenAndCa.getCryptoToken().isCryptoTokenActive()
              && !tokenAndCa.getCryptoToken().isStateChangeDisabled()) {
            return true;
          }
        }
      }
    }
    return false;
  }

  /**
   * AccessRulesConstants.REGULAR_ACTIVATECA is not the best rule to check, but
   * will work as a placeholder until authorization is revamped.
   *
   * @return true if admin is authorized to {@link
   *     AccessRulesConstants#REGULAR_ACTIVATECA}
   */
  public boolean isAuthorizedToBasicFunctions() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), AccessRulesConstants.REGULAR_ACTIVATECA);
  }

  /**
   * @param anauthenticationcode code
   */
  public void setAuthenticationCode(final String anauthenticationcode) {
    this.authenticationcode = anauthenticationcode;
  }

  /**
   * @return code
   */
  public String getAuthenticationCode() {
    return "";
  }
}
