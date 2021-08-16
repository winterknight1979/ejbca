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
package org.ejbca.ui.web.admin.cryptotoken;

import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.CesecoreConfigurationHelper;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keys.token.AvailableCryptoToken;
import org.cesecore.keys.token.BaseCryptoToken;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSession;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.KeyPairInfo;
import org.cesecore.keys.token.NullCryptoToken;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.token.p11.Pkcs11SlotLabel;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.StringTools;
import org.ejbca.config.WebConfiguration;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.util.SlotList;

/**
 * JavaServer Faces Managed Bean for managing CryptoTokens. Session scoped and
 * will cache the list of tokens and keys.
 *
 * @version $Id: CryptoTokenMBean.java 30510 2018-11-15 08:20:55Z anatom $
 */
public class CryptoTokenMBean extends BaseManagedBean implements Serializable {

    /** Param. */
  private static final String CRYPTOTOKEN_LABEL_TYPE_TEXTPREFIX =
      "CRYPTOTOKEN_LABEL_TYPE_";

  /** GUI table representation of a CryptoToken that can be interacted with. */
  public final class CryptoTokenGuiInfo {
        /** Param. */
    private final CryptoTokenInfo cryptoTokenInfo;
    /** Param. */
    private final String p11LibraryAlias;
    /** Param. */
    private final boolean allowedActivation;
    /** Param. */
    private final boolean allowedDeactivation;
    /** Param. */
    private String authenticationCode;
    /** Param. */
    private final boolean referenced;

    /**
     * @param iscryptoTokenInfo Info
     * @param isp11LibraryAlias Alias
     * @param isallowedActivation Bool
     * @param isallowedDectivation Bool
     * @param isreferenced Bool
     */
    private CryptoTokenGuiInfo(
        final CryptoTokenInfo iscryptoTokenInfo,
        final String isp11LibraryAlias,
        final boolean isallowedActivation,
        final boolean isallowedDectivation,
        final boolean isreferenced) {
      this.cryptoTokenInfo = iscryptoTokenInfo;
      this.p11LibraryAlias = isp11LibraryAlias;
      this.allowedActivation = isallowedActivation;
      this.allowedDeactivation = isallowedDectivation;
      this.referenced = isreferenced;
    }

    /**
     * @return image
     */
    public String getStatusImg() {
      return getEjbcaWebBean()
          .getImagefileInfix(
              isActive() ? "status-ca-active.png" : "status-ca-offline.png");
    }

    /**
     * @return IMG
     */
    public String getAutoActivationYesImg() {
      return getEjbcaWebBean().getImagefileInfix("status-ca-active.png");
    }

    /**
     * @return ID
     */
    public Integer getCryptoTokenId() {
      return cryptoTokenInfo.getCryptoTokenId();
    }

    /**
     * @return name
     */
    public String getTokenName() {
      return cryptoTokenInfo.getName();
    }
    /**
     * @return bool
     */
    public boolean isActive() {
      return cryptoTokenInfo.isActive();
    }

    /**
     * @return bool
     */
    public boolean isAutoActivation() {
      return cryptoTokenInfo.isAutoActivation();
    }

    /**
     * @return Type
     */
    public String getTokenType() {
      return cryptoTokenInfo.getType();
    }

    /** @return A string representing slot:index:label for a P11 slot */
    public String getP11Slot() {
      return cryptoTokenInfo.getP11Slot();
    }

    /**
     * @return Type
     */
    public String getP11SlotLabelType() {
      return cryptoTokenInfo.getP11SlotLabelType();
    }

    /**
     * @return Type
     */
    public String getP11SlotLabelTypeText() {
      if (!isP11SlotType()) {
        return "";
      }
      return EjbcaJSFHelper.getBean()
          .getText()
          .get(
              CRYPTOTOKEN_LABEL_TYPE_TEXTPREFIX
                  + cryptoTokenInfo.getP11SlotLabelType());
    }

    /**
     * @return Auth
     */
    public String getP11LibraryAlias() {
      return p11LibraryAlias;
    }

    /**
     * @return Auth
     */
    public String getAuthenticationCode() {
      return authenticationCode;
    }

    /**
     * @param anauthenticationCode Auth
     */
    public void setAuthenticationCode(final String anauthenticationCode) {
      this.authenticationCode = anauthenticationCode;
    }

    /**
     * @return Bool
     */
    public boolean isAllowedActivation() {
      return allowedActivation;
    }

    /**
     * @return Bool
     */
    public boolean isAllowedDeactivation() {
      return allowedDeactivation;
    }

    /**
     * @return Bool
     */
    public boolean isReferenced() {
      return referenced;
    }

    /**
     * @return Bool
     */
    public boolean isP11SlotType() {
      return PKCS11CryptoToken.class
          .getSimpleName()
          .equals(cryptoTokenInfo.getType());
    }
  }

  /**
   * GUI edit/view representation of a CryptoToken that can be interacted with.
   */
  public final class CurrentCryptoTokenGuiInfo {
        /** Param. */
    private String name = "";
    /** Param. */
    private String type = SoftCryptoToken.class.getSimpleName();
    /** Param. */
    private String secret1 = "";
    /** Param. */
    private String secret2 = "";
    /** Param. */
    private boolean autoActivate = false;
    /** Param. */
    private boolean allowExportPrivateKey = false;
    /** Param. */
    private String p11Library = "";
    /** Param. */
    private String p11Slot = WebConfiguration.getDefaultP11SlotNumber();
    /** Param. */
    private Pkcs11SlotLabelType p11SlotLabelType =
        Pkcs11SlotLabelType.SLOT_NUMBER;
    /** Param. */
    private String p11AttributeFile = "default";
    /** Param. */
    private boolean active = false;
    /** Param. */
    private boolean referenced = false;
    /** Param. */
    private String keyPlaceholders;
    /** Param. */
    private boolean allowExplicitParameters = false;
    /** Param. */
    private boolean canGenerateKey = true;
    /** Param. */
    private String canGenerateKeyMsg = null;

    /** Constructor. */
    private CurrentCryptoTokenGuiInfo() { }

    /**
     * @return name
     */
    public String getName() {
      return name;
    }

    /**
     * @param aname name
     */
    public void setName(final String aname) {
      this.name = aname;
    }

    /**
     * @return Type
     */
    public String getType() {
      return type;
    }

    /**
     * @param atype Type
     */
    public void setType(final String atype) {
      this.type = atype;
    }

    /**
     * @return Secret
     */
    public String getSecret1() {
      return secret1;
    }

    /**
     * @param asecret1 Secret
     */
    public void setSecret1(final String asecret1) {
      this.secret1 = asecret1;
    }

    /**
     * @return secret
     */
    public String getSecret2() {
      return secret2;
    }

    /**
     * @param asecret2 secret
     */
    public void setSecret2(final String asecret2) {
      this.secret2 = asecret2;
    }

    /**
     * @return bool
     */
    public boolean isAutoActivate() {
      return autoActivate;
    }

    /**
     * @param doautoActivate bool
     */
    public void setAutoActivate(final boolean doautoActivate) {
      this.autoActivate = doautoActivate;
    }

    /**
     * @return bool
     */
    public boolean isAllowExportPrivateKey() {
      return allowExportPrivateKey;
    }

    /**
     * @param doallowExportPrivateKey bool
     */
    public void setAllowExportPrivateKey(
            final boolean doallowExportPrivateKey) {
      this.allowExportPrivateKey = doallowExportPrivateKey;
    }

    /**
     * @return Library
     */
    public String getP11Library() {
      return p11Library;
    }

    /**
     * @param ap11Library Lobrary
     */
    public void setP11Library(final String ap11Library) {
      this.p11Library = ap11Library;
    }

    /**
     * @return Slot
     */
    public String getP11Slot() {
      return p11Slot;
    }

    /**
     * @param ap11Slot Slot
     */
    public void setP11Slot(final String ap11Slot) {
      this.p11Slot = ap11Slot;
    }

    /**
     * @return Type
     */
    public String getP11SlotLabelType() {
      return p11SlotLabelType.getKey();
    }

    /**
     * @param ap11SlotLabelType Type
     */
    public void setP11SlotLabelType(final String ap11SlotLabelType) {
      this.p11SlotLabelType = Pkcs11SlotLabelType.getFromKey(ap11SlotLabelType);
    }

    /**
     * @return texy
     */
    public String getP11SlotLabelTypeText() {
      return EjbcaJSFHelper.getBean()
          .getText()
          .get(CRYPTOTOKEN_LABEL_TYPE_TEXTPREFIX + getP11SlotLabelType());
    }

    /**
     * @return file
     */
    public String getP11AttributeFile() {
      return p11AttributeFile;
    }

    /**
     * @param ap11AttributeFile File
     */
    public void setP11AttributeFile(final String ap11AttributeFile) {
      this.p11AttributeFile = ap11AttributeFile;
    }

    /**
     * @return Bool
     */
    public boolean isActive() {
      return active;
    }

    /**
     * @param isactive Bool
     */
    public void setActive(final boolean isactive) {
      this.active = isactive;
    }

    /**
     * @return bool
     */
    public boolean isReferenced() {
      return referenced;
    }

    /**
     * @param isreferenced bool
     */
    public void setReferenced(final boolean isreferenced) {
      this.referenced = isreferenced;
    }

    /**
     * @return Templates
     */
    public String getKeyPlaceholders() {
      return keyPlaceholders;
    }

    /**
     * @param keyTemplates templates
     */
    public void setKeyPlaceholders(final String keyTemplates) {
      this.keyPlaceholders = keyTemplates;
    }

    /**
     * @return bool
     */
    public boolean isAllowExplicitParameters() {
      return allowExplicitParameters;
    }

    /**
     * @param doallowExplicitParameters bool
     */
    public void setAllowExplicitParameters(
        final boolean doallowExplicitParameters) {
      this.allowExplicitParameters = doallowExplicitParameters;
    }

    /**
     * @return bool
     */
    public boolean isCanGenerateKey() {
      return canGenerateKey;
    }

    /**
     * @param acanGenerateKey Key
     */
    public void setCanGenerateKey(final boolean acanGenerateKey) {
      this.canGenerateKey = acanGenerateKey;
    }

    /**
     * @param msg message
     */
    public void setCanGenerateKeyMsg(final String msg) {
      this.canGenerateKeyMsg = msg;
    }

    /**
     * @return Param
     */
    public String getCanGenerateKeyMsg() {
      return canGenerateKeyMsg;
    }

    /**
     * @return Alias
     */
    public String getP11LibraryAlias() {
      return CryptoTokenMBean.this.getP11LibraryAlias(p11Library);
    }

    /**
     * @return Alias
     */
    public String getP11AttributeFileAlias() {
      return CryptoTokenMBean.this.getP11AttributeFileAlias(p11AttributeFile);
    }

    /**
     * @return bool
     */
    public boolean isShowSoftCryptoToken() {
      return SoftCryptoToken.class.getSimpleName().equals(getType());
    }

    /**
     * @return bool
     */
    public boolean isShowP11CryptoToken() {
      return PKCS11CryptoToken.class.getSimpleName().equals(getType());
    }

    /**
     * @return bool
     */
    public boolean isSlotOfTokenLabelType() {
      return p11SlotLabelType.equals(Pkcs11SlotLabelType.SLOT_LABEL);
    }
  }

  /** Selectable key pair GUI representation. */
  public final class KeyPairGuiInfo {
        /** Param. */
    private final String alias;
    /** Param. */
    private final String keyAlgorithm;
    /** Param. */
    private final String keySpecification; // to be displayed in GUI
    /** Param. */
    private final String rawKeySpec; // to be used for key generation
    /** Param. */
    private final String subjectKeyID;
    /** Param. */
    private final boolean placeholder;
    /** Param. */
    private boolean selected = false;

    private KeyPairGuiInfo(final KeyPairInfo keyPairInfo) {
      alias = keyPairInfo.getAlias();
      keyAlgorithm = keyPairInfo.getKeyAlgorithm();
      rawKeySpec = keyPairInfo.getKeySpecification();
      if (AlgorithmConstants.KEYALGORITHM_ECDSA.equals(
          keyPairInfo.getKeyAlgorithm())) {
        keySpecification = getEcKeySpecAliases(rawKeySpec);
      } else {
        keySpecification = rawKeySpec;
      }
      subjectKeyID = keyPairInfo.getSubjectKeyID();
      placeholder = false;
    }

    /**
     * Creates a placeholder with a template string, in the form of
     * "alias;keyspec". Placeholders are created in CryptoTokens that are
     * imported from Statedump.
     *
     * @param templateString Template
     */
    private KeyPairGuiInfo(final String templateString) {

      String[] pieces =
          templateString.split(
              "[" + CryptoToken.KEYPLACEHOLDERS_INNER_SEPARATOR + "]");
      alias = pieces[0];
      keyAlgorithm = KeyTools.keyspecToKeyalg(pieces[1]);
      rawKeySpec = KeyTools.shortenKeySpec(pieces[1]);
      if (AlgorithmConstants.KEYALGORITHM_ECDSA.equals(keyAlgorithm)) {
        keySpecification = getEcKeySpecAliases(rawKeySpec);
      } else {
        keySpecification = rawKeySpec;
      }
      subjectKeyID = "";
      placeholder = true;
    }

    /**
     * @return Alias
     */
    public String getAlias() {
      return alias;
    }

    /**
     * @return Algo
     */
    public String getKeyAlgorithm() {
      return keyAlgorithm;
    }

    /**
     * @return Spec
     */
    public String getKeySpecification() {
      return keySpecification;
    }

    /**
     * @return Spec
     */
    public String getRawKeySpec() {
      return rawKeySpec;
    }

    /**
     * @return ID
     */
    public String getSubjectKeyID() {
      return subjectKeyID;
    }

    /**
     * @return bool
     */
    public boolean isPlaceholder() {
      return placeholder;
    }

    /**
     * @return bool
     */
    public boolean isSelected() {
      return selected;
    }

    /**
     * @param isselected bool
     */
    public void setSelected(final boolean isselected) {
      this.selected = isselected;
    }
  }

  private static final long serialVersionUID = 1L;
  /** Param. */
  private static final Logger LOG = Logger.getLogger(CryptoTokenMBean.class);

  /** Param. */
  private List<CryptoTokenGuiInfo> cryptoTokenGuiInfos = new ArrayList<>();
  /** Param. */
  private ListDataModel<CryptoTokenGuiInfo> cryptoTokenGuiList = null;
  /** Param. */
  private List<KeyPairGuiInfo> keyPairGuiInfos = new ArrayList<>();
  /** Param. */
  private ListDataModel<KeyPairGuiInfo> keyPairGuiList = null;
  /** Param. */
  private String keyPairGuiListError = null;
  /** Param. */
  private int currentCryptoTokenId = 0;
  /** Param. */
  private CurrentCryptoTokenGuiInfo currentCryptoToken = null;
  /** Param. */
  private boolean p11SlotUsed =
      false; // Note if the P11 slot is already used by another crypto token,
             // forcing a confirm
  /** Param. */
  private boolean currentCryptoTokenEditMode =
      true; // currentCryptoTokenId==0 from start

  /** Param. */
  private final CryptoTokenManagementSessionLocal cryptoTokenManagementSession =
      getEjbcaWebBean().getEjb().getCryptoTokenManagementSession();
  /** Param. */
  private final AuthorizationSessionLocal authorizationSession =
      getEjbcaWebBean().getEjb().getAuthorizationSession();
  /** Param. */
  private final AuthenticationToken authenticationToken = getAdmin();
  /** Param. */
  private final CaSessionLocal caSession =
      getEjbcaWebBean().getEjb().getCaSession();
  /** Param. */
  private final InternalKeyBindingMgmtSessionLocal
      internalKeyBindingMgmtSession =
          getEjbcaWebBean().getEjb().getInternalKeyBindingMgmtSession();

  /**
   * Workaround to cache the items used to render the page long enough for
   * actions to be able to use them, but reload on every page view.
   *
   * @return bool
   */
  public boolean isPageLoadResetTrigger() {
    flushCaches();
    return false;
  }

  /** Force reload from underlying (cache) layer. */
  private void flushCaches() {
    cryptoTokenGuiList = null;
    flushCurrent();
  }

  /**
   * Force reload from underlying (cache) layer for the current CryptoToken and
   * its list of key pairs.
   */
  private void flushCurrent() {
    keyPairGuiList = null;
    currentCryptoToken = null;
    p11SlotUsed = false;
  }

  /** @return a List of all CryptoToken Identifiers referenced by CAs. */
  private List<Integer> getReferencedCryptoTokenIds() {
    final List<Integer> ret = new ArrayList<>();
    // Add all CryptoToken ids referenced by CAs
    for (int caId : caSession.getAllCaIds()) {
      final CAInfo cainfo = caSession.getCAInfoInternal(caId);
      // We may have CAIds that can not be resolved to a real CA, for example
      // CVC CAs on Community
      if (cainfo != null) {
        ret.add(Integer.valueOf(cainfo.getCAToken().getCryptoTokenId()));
      }
    }
    // Add all CryptoToken ids referenced by InternalKeyBindings
    for (final String internalKeyBindingType
        : internalKeyBindingMgmtSession
            .getAvailableTypesAndProperties()
            .keySet()) {
      for (final InternalKeyBindingInfo internalKeyBindingInfo
          : internalKeyBindingMgmtSession.getAllInternalKeyBindingInfos(
              internalKeyBindingType)) {
        ret.add(Integer.valueOf(internalKeyBindingInfo.getCryptoTokenId()));
      }
    }
    // In the future other components that use CryptoTokens should be checked
    // here as well!
    return ret;
  }

  /**
   * Build a list sorted by name from the authorized cryptoTokens that can be
   * presented to the user.
   *
   * @return Model
   */
  public ListDataModel<CryptoTokenGuiInfo> getCryptoTokenGuiList() {
    if (cryptoTokenGuiList == null) {
      final List<Integer> referencedCryptoTokenIds =
          getReferencedCryptoTokenIds();
      final List<CryptoTokenGuiInfo> list = new ArrayList<>();
      for (final CryptoTokenInfo cryptoTokenInfo
          : cryptoTokenManagementSession.getCryptoTokenInfos(
              authenticationToken)) {
        final String p11LibraryAlias =
            getP11LibraryAlias(cryptoTokenInfo.getP11Library());
        final boolean allowedActivation =
            authorizationSession.isAuthorizedNoLogging(
                authenticationToken,
                CryptoTokenRules.ACTIVATE
                    + "/"
                    + cryptoTokenInfo.getCryptoTokenId().toString());
        final boolean allowedDeactivation =
            authorizationSession.isAuthorizedNoLogging(
                authenticationToken,
                CryptoTokenRules.DEACTIVATE
                    + "/"
                    + cryptoTokenInfo.getCryptoTokenId().toString());
        final boolean referenced =
            referencedCryptoTokenIds.contains(
                Integer.valueOf(cryptoTokenInfo.getCryptoTokenId()));
        list.add(
            new CryptoTokenGuiInfo(
                cryptoTokenInfo,
                p11LibraryAlias,
                allowedActivation,
                allowedDeactivation,
                referenced));
        Collections.sort(
            list,
            new Comparator<CryptoTokenGuiInfo>() {
              @Override
              public int compare(
                  final CryptoTokenGuiInfo cryptoTokenInfo1,
                  final CryptoTokenGuiInfo cryptoTokenInfo2) {
                return cryptoTokenInfo1
                    .getTokenName()
                    .compareToIgnoreCase(cryptoTokenInfo2.getTokenName());
              }
            });
      }
      cryptoTokenGuiInfos = list;
      cryptoTokenGuiList = new ListDataModel<>(cryptoTokenGuiInfos);
    }
    // If show the list, then we are on the main page and want to flush the two
    // caches
    flushCurrent();
    setCurrentCryptoTokenEditMode(false);
    return cryptoTokenGuiList;
  }

  /**
   * Invoked when admin requests a CryptoToken activation.
   *
   * @throws AuthorizationDeniedException fail
   */
  public void activateCryptoToken() throws AuthorizationDeniedException {
    if (cryptoTokenGuiList != null) {
      final CryptoTokenGuiInfo current = cryptoTokenGuiList.getRowData();
      try {
        cryptoTokenManagementSession.activate(
            authenticationToken,
            current.getCryptoTokenId(),
            current.getAuthenticationCode().toCharArray());
      } catch (CryptoTokenOfflineException e) {
        final String msg =
            "Activation of CryptoToken '"
                + current.getTokenName()
                + "' ("
                + current.getCryptoTokenId()
                + ") by administrator "
                + authenticationToken.toString()
                + " failed. Device was unavailable.";
        super.addNonTranslatedErrorMessage(msg);
        LOG.info(msg);
      } catch (CryptoTokenAuthenticationFailedException e) {
        final String msg =
            "Activation of CryptoToken '"
                + current.getTokenName()
                + "' ("
                + current.getCryptoTokenId()
                + ") by administrator "
                + authenticationToken.toString()
                + " failed. Authentication code was not correct.";
        super.addNonTranslatedErrorMessage(msg);
        LOG.info(msg);
      }
      flushCaches();
    }
  }

  /**
   * Invoked when admin requests a CryptoToken deactivation.
   *
   * @throws AuthorizationDeniedException Fail
   */
  public void deactivateCryptoToken() throws AuthorizationDeniedException {
    if (cryptoTokenGuiList != null) {
      final CryptoTokenGuiInfo rowData = cryptoTokenGuiList.getRowData();
      cryptoTokenManagementSession.deactivate(
          authenticationToken, rowData.getCryptoTokenId());
      flushCaches();
    }
  }

  /**
   * Invoked when admin requests a CryptoToken deletion.
   *
   * @throws AuthorizationDeniedException Fail
   */
  public void deleteCryptoToken() throws AuthorizationDeniedException {
    if (cryptoTokenGuiList != null) {
      final CryptoTokenGuiInfo rowData = cryptoTokenGuiList.getRowData();
      cryptoTokenManagementSession.deleteCryptoToken(
          authenticationToken, rowData.getCryptoTokenId());
      flushCaches();
    }
  }

  /** @return true if admin may create new or modify existing CryptoTokens. */
  public boolean isAllowedToModify() {
    return authorizationSession.isAuthorizedNoLogging(
        authenticationToken, CryptoTokenRules.MODIFY_CRYPTOTOKEN.resource());
  }

  /** @return true if admin may delete CryptoTokens. */
  public boolean isAllowedToDelete() {
    return authorizationSession.isAuthorizedNoLogging(
        authenticationToken, CryptoTokenRules.DELETE_CRYPTOTOKEN.resource());
  }

  /**
   * @throws AuthorizationDeniedException fail
   */
  public void saveCurrentCryptoTokenWithCheck()
      throws AuthorizationDeniedException {
    saveCurrentCryptoToken(true);
  }

  /**
   * @throws AuthorizationDeniedException fail
   */
  public void saveCurrentCryptoToken() throws AuthorizationDeniedException {
    saveCurrentCryptoToken(false);
  }

  /**
   * Invoked when admin requests a CryptoToken creation.
   *
   * @param checkSlotInUse bool
   * @throws AuthorizationDeniedException Fail
   */
  private void saveCurrentCryptoToken(final boolean checkSlotInUse)
      throws AuthorizationDeniedException {
    String msg = null;
    if (!getCurrentCryptoToken()
        .getSecret1()
        .equals(getCurrentCryptoToken().getSecret2())) {
      msg = "Authentication codes do not match!";
    } else {
      try {
        final String name = getCurrentCryptoToken().getName();
        final Properties properties = new Properties();
        String className = null;
        boolean alreadyUsed = false;
        if (PKCS11CryptoToken.class
            .getSimpleName()
            .equals(getCurrentCryptoToken().getType())) {
          className = PKCS11CryptoToken.class.getName();
          String library = getCurrentCryptoToken().getP11Library();
          properties.setProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY, library);
          String slotTextValue = getCurrentCryptoToken().getP11Slot().trim();
          String slotLabelType = getCurrentCryptoToken().getP11SlotLabelType();
          // Perform some name validation
          if (slotLabelType.equals(Pkcs11SlotLabelType.SLOT_NUMBER.getKey())) {
            if (!Pkcs11SlotLabelType.SLOT_NUMBER.validate(slotTextValue)) {
              msg = "Slot must be an absolute number";
            }
          } else if (slotLabelType.equals(
              Pkcs11SlotLabelType.SLOT_INDEX.getKey())) {
            if (slotTextValue.charAt(0) != 'i') {
              slotTextValue = "i" + slotTextValue;
            }
            if (!Pkcs11SlotLabelType.SLOT_INDEX.validate(slotTextValue)) {
              msg =
                  "Slot must be an absolute number or use prefix 'i' for"
                      + " indexed slots.";
            }
          }

          // Verify that it is allowed
          SlotList allowedSlots = getP11SlotList();
          if (allowedSlots != null && !allowedSlots.contains(slotTextValue)) {
            throw new IllegalArgumentException(
                "Slot number "
                    + slotTextValue
                    + " is not allowed. Allowed slots are: "
                    + allowedSlots);
          }

          properties.setProperty(
              PKCS11CryptoToken.SLOT_LABEL_VALUE, slotTextValue);
          properties.setProperty(
              PKCS11CryptoToken.SLOT_LABEL_TYPE, slotLabelType);
          // The default should be null, but we will get a value "default" from
          // the GUI code in this case..
          final String p11AttributeFile =
              getCurrentCryptoToken().getP11AttributeFile();
          if (!"default".equals(p11AttributeFile)) {
            properties.setProperty(
                PKCS11CryptoToken.ATTRIB_LABEL_KEY, p11AttributeFile);
          }
          if (checkSlotInUse) {
            LOG.info("Checking if slot is already used");
            List<String> usedBy =
                cryptoTokenManagementSession.isCryptoTokenSlotUsed(
                    authenticationToken, name, className, properties);
            if (!usedBy.isEmpty()) {
              msg = "The P11 slot is already used by other crypto token(s)";
              for (String cryptoTokenName : usedBy) {
                String usedByName = cryptoTokenName;
                if (StringUtils.isNumeric(usedByName)) {
                  // if the crypto token name is purely numeric, it is likely to
                  // be a database protection token
                  usedByName = usedByName + " (database protection?)";
                }
                msg += "; " + usedByName;
              }
              msg +=
                  ". Re-using P11 slots in multiple crypto tokens is"
                      + " discouraged, and all parameters must be identical."
                      + " Re-enter authentication code and Confirm Save to"
                      + " continue.";
              alreadyUsed = true;
              p11SlotUsed = true;
            }
          }
        } else if (SoftCryptoToken.class
            .getSimpleName()
            .equals(getCurrentCryptoToken().getType())) {
          className = SoftCryptoToken.class.getName();
          properties.setProperty(SoftCryptoToken.NODEFAULTPWD, "true");
        }
        if (getCurrentCryptoToken().isAllowExportPrivateKey()) {
          properties.setProperty(
              CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY,
              String.valueOf(
                  getCurrentCryptoToken().isAllowExportPrivateKey()));
        }
        if (getCurrentCryptoToken().getKeyPlaceholders() != null) {
          properties.setProperty(
              CryptoToken.KEYPLACEHOLDERS_PROPERTY,
              getCurrentCryptoToken().getKeyPlaceholders());
        }
        if (getCurrentCryptoToken().isAllowExplicitParameters()) {
          properties.setProperty(
              CryptoToken.EXPLICIT_ECC_PUBLICKEY_PARAMETERS,
              String.valueOf(
                  getCurrentCryptoToken().isAllowExplicitParameters()));
        }

        if (!alreadyUsed) {
          final char[] secret =
              getCurrentCryptoToken().getSecret1().toCharArray();
          if (getCurrentCryptoTokenId() == 0) {
            if (secret.length > 0) {
              if (getCurrentCryptoToken().isAutoActivate()) {
                BaseCryptoToken.setAutoActivatePin(
                    properties, new String(secret), true);
              }
              currentCryptoTokenId =
                  cryptoTokenManagementSession.createCryptoToken(
                      authenticationToken,
                      name,
                      className,
                      properties,
                      null,
                      secret);
              msg = "CryptoToken created successfully.";
            } else {
              super.addNonTranslatedErrorMessage(
                  "You must provide an authentication code to create a"
                      + " CryptoToken.");
            }
          } else {
            if (getCurrentCryptoToken().isAutoActivate()) {
              if (secret.length > 0) {
                BaseCryptoToken.setAutoActivatePin(
                    properties, new String(secret), true);
              } else {
                // Indicate that we want to reuse current auto-pin if present
                properties.put(
                    CryptoTokenManagementSession.KEEP_AUTO_ACTIVATION_PIN,
                    Boolean.TRUE.toString());
              }
            }
            cryptoTokenManagementSession.saveCryptoToken(
                authenticationToken,
                getCurrentCryptoTokenId(),
                name,
                properties,
                secret);
            msg = "CryptoToken saved successfully.";
          }
          flushCaches();
          setCurrentCryptoTokenEditMode(false);
        }
      } catch (CryptoTokenOfflineException e) {
        msg = e.getMessage();
      } catch (CryptoTokenAuthenticationFailedException e) {
        msg = e.getMessage();
      } catch (AuthorizationDeniedException e) {
        msg = e.getMessage();
      } catch (IllegalArgumentException e) {
        msg = e.getMessage();
      } catch (Throwable e) {
        msg = e.getMessage();
        LOG.info("", e);
      }
    }
    if (msg != null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Message displayed to user: " + msg);
      }
      super.addNonTranslatedErrorMessage(msg);
    }
  }

  /** Invoked when admin cancels a CryptoToken create or edit. */
  public void cancelCurrentCryptoToken() {
    setCurrentCryptoTokenEditMode(false);
    flushCaches();
  }

  /**
   * @return bool
   */
  public boolean isAnyP11LibraryAvailable() {
    return !getAvailableCryptoTokenP11Libraries().isEmpty();
  }

  /**
   * @return a list of library SelectItems sort by display name for detected P11
   *     libraries.
   */
  public List<SelectItem> getAvailableCryptoTokenP11Libraries() {
    final List<SelectItem> ret = new ArrayList<>();
    for (Entry<String, WebConfiguration.P11LibraryInfo> entry
        : WebConfiguration.getAvailableP11LibraryToAliasMap().entrySet()) {
      ret.add(new SelectItem(entry.getKey(), entry.getValue().getAlias()));
    }
    // Sort by display name
    Collections.sort(
        ret,
        new Comparator<SelectItem>() {
          @Override
          public int compare(final SelectItem s0, final SelectItem s1) {
            return String.valueOf(s0.getValue()).compareTo(String.valueOf(s1));
          }
        });
    return ret;
  }

  /**
   * @param library Library
   * @return alias if present otherwise the filename
   */
  private String getP11LibraryAlias(final String library) {
    if (library == null) {
      return "";
    }

    WebConfiguration.P11LibraryInfo libinfo =
        WebConfiguration.getAvailableP11LibraryToAliasMap().get(library);
    if (libinfo == null) {
        return library;
    }
    String alias = libinfo.getAlias();
    if (alias == null || alias.isEmpty()) {
        return library;
    }
    return alias;
  }

  /**
   * @return a list of library SelectItems sort by display name for detected P11
   *     libraries.
   */
  public List<SelectItem> getAvailableCryptoTokenP11AttributeFiles() {
    final List<SelectItem> ret = new ArrayList<>();
    ret.add(new SelectItem("default", "Default"));
    for (Entry<String, String> entry
        : WebConfiguration.getAvailableP11AttributeFiles().entrySet()) {
      ret.add(new SelectItem(entry.getKey(), entry.getValue()));
    }
    // Sort by display name
    Collections.sort(
        ret,
        new Comparator<SelectItem>() {
          @Override
          public int compare(final SelectItem s0, final SelectItem s1) {
            return String.valueOf(s0.getValue()).compareTo(String.valueOf(s1));
          }
        });
    return ret;
  }

  /**
   * @return Types
   */
  public List<SelectItem> getAvailableCryptoTokenP11SlotLabelTypes() {
    final List<SelectItem> ret = new ArrayList<>();
    for (Pkcs11SlotLabelType type : Pkcs11SlotLabelType.values()) {
      if (type.equals(Pkcs11SlotLabelType.SUN_FILE)) {
        // jeklund doesn't believe that this is used anywhere, but he might be
        // wrong
        continue;
      }
      final String display =
          EjbcaJSFHelper.getBean()
              .getText()
              .get(CRYPTOTOKEN_LABEL_TYPE_TEXTPREFIX + type.name());
      ret.add(new SelectItem(type.name(), display));
    }
    return ret;
  }

  /**
   * Tries to retrieve the list of PKCS#11 slots (including token labels) using
   * the Sun PKCS#11 Wrapper.
   *
   * @return Labels
   */
  public List<SelectItem> getAvailableCryptoTokenP11SlotTokenLabels() {
    final List<SelectItem> ret = new ArrayList<>();
    try {
      final File p11Library = new File(currentCryptoToken.getP11Library());
      SlotList allowedSlots = getP11SlotList();
      if (p11Library.exists()) {
        int index = 0;
        for (final String extendedTokenLabel
            : Pkcs11SlotLabel.getExtendedTokenLabels(p11Library)) {
          // Returned list is in form "slotId;tokenLabel"
          final String slotId =
              extendedTokenLabel.substring(0, extendedTokenLabel.indexOf(';'));
          final String tokenLabel =
              extendedTokenLabel.substring(extendedTokenLabel.indexOf(';') + 1);
          if (!tokenLabel.isEmpty()) {
            // Bravely assume that slots without a token label are not
            // initialized or irrelevant
            if (allowedSlots == null || allowedSlots.contains(slotId)) {
              // Only show white-listed slots
              ret.add(
                  new SelectItem(
                      tokenLabel,
                      tokenLabel
                          + " (index="
                          + index
                          + ", id="
                          + slotId
                          + ")"));
            }
          }
          index++;
        }
      }
    } catch (Exception e) {
      LOG.info(
          "Administrator "
              + authenticationToken.toString()
              + " tries to list pkcs#11 slots using token label. Failed with: ",
          e);
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(
                  FacesMessage.SEVERITY_ERROR,
                  "Unable to retrieve token labels.",
                  ""));
    }
    return ret;
  }

  /**
   * @param p11AttributeFile File
   * @return alias if present otherwise the filename
   */
  public String getP11AttributeFileAlias(final String p11AttributeFile) {
    if (p11AttributeFile == null || p11AttributeFile.length() == 0) {
      return "Default";
    }
    String ret =
        WebConfiguration.getAvailableP11AttributeFiles().get(p11AttributeFile);
    if (ret == null || ret.length() == 0) {
      ret = p11AttributeFile;
    }
    return ret;
  }

  /** @return a list of usable CryptoToken types */
  public List<SelectItem> getAvailableCryptoTokenTypes() {
    final List<SelectItem> ret = new ArrayList<>();
    final Collection<AvailableCryptoToken> availableCryptoTokens =
        CryptoTokenFactory.instance().getAvailableCryptoTokens();
    for (AvailableCryptoToken availableCryptoToken : availableCryptoTokens) {
      if (availableCryptoToken
          .getClassPath()
          .equals(NullCryptoToken.class.getName())) {
        // Special case: Never expose the NullCryptoToken when creating new
        // tokens
        continue;
      }
      if (availableCryptoToken
          .getClassPath()
          .equals(PKCS11CryptoToken.class.getName())) {
        // Special case: Never expose the PKCS11CryptoToken when creating new
        // tokens if no libraries are detected
        if (!isAnyP11LibraryAvailable()) {
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "No known PKCS#11 libraries are available, not enabling"
                    + " PKCS#11 support in GUI. See web.properties for"
                    + " configuration of new PKCS#11 libraries.");
          }
          continue;
        }
      }
      // Use one the class's simpleName
      final String fullClassName = availableCryptoToken.getClassPath();
      ret.add(
          new SelectItem(
              fullClassName.substring(fullClassName.lastIndexOf('.') + 1),
              availableCryptoToken.getName()));
    }
    return ret;
  }

  /**
   * Used to draw the back link. No white-listing to the calling method must be
   * careful to only use this for branching.
   *
   * @return Ref
   */
  public String getParamRef() {
    final String reference =
        FacesContext.getCurrentInstance()
            .getExternalContext()
            .getRequestParameterMap()
            .get("ref");
    if (reference == null || reference.isEmpty()) {
      return "default";
    }
    return reference;
  }

  /** @return the id of the CryptoToken that is subject to view or edit */
  public int getCurrentCryptoTokenId() {
    // Get the HTTP GET/POST parameter named "cryptoTokenId"
    final String cryptoTokenIdString =
        FacesContext.getCurrentInstance()
            .getExternalContext()
            .getRequestParameterMap()
            .get("cryptoTokenId");
    if (cryptoTokenIdString != null && cryptoTokenIdString.length() > 0) {
      try {
        int acurrentCryptoTokenId = Integer.parseInt(cryptoTokenIdString);
        // If there is a query parameter present and the id is different we
        // flush the cache!
        if (acurrentCryptoTokenId != this.currentCryptoTokenId) {
          flushCaches();
          this.currentCryptoTokenId = acurrentCryptoTokenId;
        }
        // Always switch to edit mode for new ones and view mode for all others
        setCurrentCryptoTokenEditMode(acurrentCryptoTokenId == 0);
      } catch (NumberFormatException e) {
        LOG.info(
            "Bad 'cryptoTokenId' parameter value.. set, but not a number..");
      }
    }
    return currentCryptoTokenId;
  }

  /**
   * @return cached or populate a new CryptoToken GUI representation for view or
   *     edit
   * @throws AuthorizationDeniedException Fail
   */
  public CurrentCryptoTokenGuiInfo getCurrentCryptoToken()
      throws AuthorizationDeniedException {
    if (this.currentCryptoToken == null) {
      final int cryptoTokenId = getCurrentCryptoTokenId();
      final CurrentCryptoTokenGuiInfo acurrentCryptoToken =
          new CurrentCryptoTokenGuiInfo();
      // If the id is non-zero we try to load an existing token
      if (cryptoTokenId != 0) {
        final CryptoTokenInfo cryptoTokenInfo =
            cryptoTokenManagementSession.getCryptoTokenInfo(
                authenticationToken, cryptoTokenId);
        if (cryptoTokenInfo == null) {
          throw new RuntimeException(
              "Could not load CryptoToken with cryptoTokenId " + cryptoTokenId);
        } else {
          acurrentCryptoToken.setAllowExportPrivateKey(
              cryptoTokenInfo.isAllowExportPrivateKey());
          acurrentCryptoToken.setAutoActivate(
              cryptoTokenInfo.isAutoActivation());
          acurrentCryptoToken.setSecret1("");
          acurrentCryptoToken.setSecret2("");
          acurrentCryptoToken.setName(cryptoTokenInfo.getName());
          acurrentCryptoToken.setType(cryptoTokenInfo.getType());
          acurrentCryptoToken.setKeyPlaceholders(
              cryptoTokenInfo
                  .getCryptoTokenProperties()
                  .getProperty(CryptoToken.KEYPLACEHOLDERS_PROPERTY, ""));
          acurrentCryptoToken.setAllowExplicitParameters(
              cryptoTokenInfo.isAllowExplicitParameters());

          if (cryptoTokenInfo
              .getType()
              .equals(PKCS11CryptoToken.class.getSimpleName())) {
            acurrentCryptoToken.setP11AttributeFile(
                cryptoTokenInfo.getP11AttributeFile());
            acurrentCryptoToken.setP11Library(cryptoTokenInfo.getP11Library());
            acurrentCryptoToken.setP11Slot(cryptoTokenInfo.getP11Slot());
            acurrentCryptoToken.setP11SlotLabelType(
                cryptoTokenInfo.getP11SlotLabelType());
            // Extra capabilities not stored in the crypto token, but defined
            // for this type of P11 crypto token
            WebConfiguration.P11LibraryInfo libinfo =
                WebConfiguration.getAvailableP11LibraryToAliasMap()
                    .get(acurrentCryptoToken.getP11Library());
            acurrentCryptoToken.setCanGenerateKey(libinfo.isCanGenerateKey());
            acurrentCryptoToken.setCanGenerateKeyMsg(
                libinfo.getCanGenerateKeyMsg());
          }
          acurrentCryptoToken.setActive(cryptoTokenInfo.isActive());
          acurrentCryptoToken.setReferenced(
              getReferencedCryptoTokenIds()
                  .contains(Integer.valueOf(cryptoTokenId)));
        }
      }
      this.currentCryptoToken = acurrentCryptoToken;
    }
    return this.currentCryptoToken;
  }

  /**
   * Select.
   */
  public void selectCryptoTokenType() {
    // NOOP: Only for page reload
  }

  /** Select.
   */
  public void selectCryptoTokenLabelType() {
    // Clear slot reference when we change type
    currentCryptoToken.setP11Slot("");
  }

  /**
   * @return bool
   */
  public boolean isCurrentCryptoTokenEditMode() {
    return currentCryptoTokenEditMode;
  }

  /**
   * @param acurrentCryptoTokenEditMode mode
   */
  public void setCurrentCryptoTokenEditMode(
      final boolean acurrentCryptoTokenEditMode) {
    this.currentCryptoTokenEditMode = acurrentCryptoTokenEditMode;
  }

  /** Toggle. */
  public void toggleCurrentCryptoTokenEditMode() {
    currentCryptoTokenEditMode ^= true;
  }

  //
  // KeyPair related stuff
  //

  // This default is taken from CAToken.SOFTPRIVATESIGNKEYALIAS, but we don't
  // want to depend on the CA module
  /** Param. */
  private String newKeyPairAlias = "signKey";
  /** Param. */
  private String newKeyPairSpec = AlgorithmConstants.KEYALGORITHM_RSA + "4096";

  /**
   * @return a List of available (but not necessarily supported by the
   *     underlying CryptoToken) key specs
   */
  public List<SelectItem> getAvailableKeySpecs() {
    final List<SelectItem> availableKeySpecs = new ArrayList<>();
    final int[] sizesRSA = {1024, 1536, 2048, 3072, 4096, 6144, 8192};
    final int[] sizesDSA = {1024};
    for (int size : sizesRSA) {
      availableKeySpecs.add(
          new SelectItem(
              AlgorithmConstants.KEYALGORITHM_RSA + size,
              AlgorithmConstants.KEYALGORITHM_RSA + " " + size));
    }
    for (int size : sizesDSA) {
      availableKeySpecs.add(
          new SelectItem(
              AlgorithmConstants.KEYALGORITHM_DSA + size,
              AlgorithmConstants.KEYALGORITHM_DSA + " " + size));
    }
    try {
      final Map<String, List<String>> namedEcCurvesMap =
          AlgorithmTools.getNamedEcCurvesMap(
              PKCS11CryptoToken.class
                  .getSimpleName()
                  .equals(getCurrentCryptoToken().getType()));
      final String[] keys =
          namedEcCurvesMap
              .keySet()
              .toArray(new String[namedEcCurvesMap.size()]);
      Arrays.sort(keys);
      for (final String name : keys) {
        availableKeySpecs.add(
            new SelectItem(
                name,
                AlgorithmConstants.KEYALGORITHM_ECDSA
                    + " "
                    + StringTools.getAsStringWithSeparator(
                        " / ", namedEcCurvesMap.get(name))));
      }
    } catch (AuthorizationDeniedException e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Ignoring exception " + e.getMessage());
      }
    }
    for (String alg : CesecoreConfigurationHelper.getExtraAlgs()) {
      for (String subalg : CesecoreConfigurationHelper.getExtraAlgSubAlgs(alg)) {
        final String title =
            CesecoreConfigurationHelper.getExtraAlgSubAlgTitle(alg, subalg);
        final String name =
            CesecoreConfigurationHelper.getExtraAlgSubAlgName(alg, subalg);
        availableKeySpecs.add(new SelectItem(name, title));
      }
    }
    return availableKeySpecs;
  }

  private String getEcKeySpecAliases(final String ecKeySpec) {
    StringBuilder ret = new StringBuilder();
    for (final String alias : AlgorithmTools.getEcKeySpecAliases(ecKeySpec)) {
      if (ret.length() != 0) {
        ret.append(" / ");
      }
      ret.append(alias);
    }
    return ret.toString();
  }

  /** @return true if admin may generate keys in the current CryptoTokens. */
  public boolean isAllowedToKeyGeneration() {
    return authorizationSession.isAuthorizedNoLogging(
        authenticationToken,
        CryptoTokenRules.GENERATE_KEYS.resource()
            + '/'
            + getCurrentCryptoTokenId());
  }

  /** @return true if admin may test keys from the current CryptoTokens. */
  public boolean isAllowedToKeyTest() {
    return authorizationSession.isAuthorizedNoLogging(
        authenticationToken,
        CryptoTokenRules.TEST_KEYS.resource()
            + '/'
            + getCurrentCryptoTokenId());
  }

  /** @return true if admin may remove keys from the current CryptoTokens. */
  public boolean isAllowedToKeyRemoval() {
    return authorizationSession.isAuthorizedNoLogging(
        authenticationToken,
        CryptoTokenRules.REMOVE_KEYS.resource()
            + '/'
            + getCurrentCryptoTokenId());
  }

  /**
   * @return bool
   * @throws AuthorizationDeniedException fail
   */
  public boolean isKeyPairGuiListEmpty() throws AuthorizationDeniedException {
    return getKeyPairGuiList().getRowCount() == 0;
  }

  /**
   * @return bool
   * @throws AuthorizationDeniedException fail
   */
  public boolean isKeyPairGuiListFailed() throws AuthorizationDeniedException {
    getKeyPairGuiList(); // ensure loaded
    return keyPairGuiListError != null;
  }

  /**
   * @return Error
   * @throws AuthorizationDeniedException Fail
   */
  public String getKeyPairGuiListError() throws AuthorizationDeniedException {
    getKeyPairGuiList(); // ensure loaded
    return keyPairGuiListError;
  }

  /**
   * @return a list of all the keys in the current CryptoToken.
   * @throws AuthorizationDeniedException Fail
   */
  public ListDataModel<KeyPairGuiInfo> getKeyPairGuiList()
      throws AuthorizationDeniedException {
    if (keyPairGuiList == null) {
      final List<KeyPairGuiInfo> ret = new ArrayList<>();
      if (getCurrentCryptoToken().isActive()) {
        // Add existing key pairs
        try {
          for (KeyPairInfo keyPairInfo
             : cryptoTokenManagementSession.getKeyPairInfos(
                  getAdmin(), getCurrentCryptoTokenId())) {
            ret.add(new KeyPairGuiInfo(keyPairInfo));
          }
        } catch (CryptoTokenOfflineException ctoe) {
          keyPairGuiListError =
              "Failed to load key pairs from CryptoToken: " + ctoe.getMessage();
        }
        // Add placeholders for key pairs
        String keyPlaceholders = getCurrentCryptoToken().getKeyPlaceholders();
        for (String template
            : keyPlaceholders.split(
                "[" + CryptoToken.KEYPLACEHOLDERS_OUTER_SEPARATOR + "]")) {
          if (!template.trim().isEmpty()) {
            ret.add(new KeyPairGuiInfo(template));
          }
        }
      }
      Collections.sort(
          ret,
          new Comparator<KeyPairGuiInfo>() {
            @Override
            public int compare(
                final KeyPairGuiInfo keyPairInfo1,
                final KeyPairGuiInfo keyPairInfo2) {
              return keyPairInfo1.getAlias().compareTo(keyPairInfo2.getAlias());
            }
          });
      keyPairGuiInfos = ret;
      keyPairGuiList = new ListDataModel<>(keyPairGuiInfos);
    }
    return keyPairGuiList;
  }

  /**
   * @return spec
   */
  public String getNewKeyPairSpec() {
    return newKeyPairSpec;
  }

  /**
   * @param anewKeyPairSpec spec
   */
  public void setNewKeyPairSpec(final String anewKeyPairSpec) {
    this.newKeyPairSpec = anewKeyPairSpec;
  }

  /**
   *
   * @return alias
   */
  public String getNewKeyPairAlias() {
    return newKeyPairAlias;
  }

  /**
   * @param anewKeyPairAlias Alias
   */
  public void setNewKeyPairAlias(final String anewKeyPairAlias) {
    this.newKeyPairAlias = anewKeyPairAlias;
  }

  /** Invoked when admin requests a new key pair generation. */
  public void generateNewKeyPair() {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">generateNewKeyPair");
    }
    try {
      cryptoTokenManagementSession.createKeyPair(
          getAdmin(),
          getCurrentCryptoTokenId(),
          getNewKeyPairAlias(),
          getNewKeyPairSpec());
    } catch (CryptoTokenOfflineException e) {
      super.addNonTranslatedErrorMessage(
          "Token is off-line. KeyPair cannot be generated.");
    } catch (Exception e) {
      super.addNonTranslatedErrorMessage(e.getMessage());
      final String logMsg =
          getAdmin().toString() + " failed to generate a keypair:";
      if (LOG.isDebugEnabled()) {
        LOG.debug(logMsg, e);
      } else {
        LOG.info(logMsg + e.getMessage());
      }
    }
    flushCaches();
    if (LOG.isTraceEnabled()) {
      LOG.trace("<generateNewKeyPair");
    }
  }

  /**
   * Invoked when admin requests key pair generation
   * from a template placeholder.
   */
  public void generateFromTemplate() {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">generateFromTemplate");
    }
    final KeyPairGuiInfo keyPairGuiInfo = keyPairGuiList.getRowData();
    final String alias = keyPairGuiInfo.getAlias();
    final String keyspec =
        KeyTools.keyalgspecToKeyspec(
            keyPairGuiInfo.getKeyAlgorithm(), keyPairGuiInfo.getRawKeySpec());
    try {
      cryptoTokenManagementSession.createKeyPairFromTemplate(
          getAdmin(), getCurrentCryptoTokenId(), alias, keyspec);
    } catch (CryptoTokenOfflineException e) {
      super.addNonTranslatedErrorMessage(
          "Token is off-line. KeyPair cannot be generated.");
    } catch (Exception e) {
      super.addNonTranslatedErrorMessage(e.getMessage());
      final String logMsg =
          getAdmin().toString() + " failed to generate a keypair:";
      if (LOG.isDebugEnabled()) {
        LOG.debug(logMsg, e);
      } else {
        LOG.info(logMsg + e.getMessage());
      }
    }
    flushCaches();
    if (LOG.isTraceEnabled()) {
      LOG.trace("<generateFromTemplate");
    }
  }

  /** Invoked when admin requests a test of a key pair. */
  public void testKeyPair() {
    final KeyPairGuiInfo keyPairGuiInfo = keyPairGuiList.getRowData();
    final String alias = keyPairGuiInfo.getAlias();
    try {
      cryptoTokenManagementSession.testKeyPair(
          getAdmin(), getCurrentCryptoTokenId(), alias);
      super.addNonTranslatedInfoMessage(alias + " tested successfully.");
    } catch (Exception e) {
      super.addNonTranslatedErrorMessage(e.getMessage());
    }
  }

  /** Invoked when admin requests the removal of a key pair. */
  public void removeKeyPair() {
    final KeyPairGuiInfo keyPairGuiInfo = keyPairGuiList.getRowData();
    final String alias = keyPairGuiInfo.getAlias();
    try {
      if (!keyPairGuiInfo.isPlaceholder()) {
        cryptoTokenManagementSession.removeKeyPair(
            getAdmin(), getCurrentCryptoTokenId(), alias);
      } else {
        cryptoTokenManagementSession.removeKeyPairPlaceholder(
            getAdmin(), getCurrentCryptoTokenId(), alias);
      }
      flushCaches();
    } catch (Exception e) {
      super.addNonTranslatedErrorMessage(e.getMessage());
    }
  }

  /** Invoked when admin requests the removal of multiple key pair. */
  public void removeSelectedKeyPairs() {
    if (keyPairGuiInfos != null) {
      for (KeyPairGuiInfo cryptoTokenKeyPairInfo : keyPairGuiInfos) {
        if (cryptoTokenKeyPairInfo.isSelected()) {
          try {
            cryptoTokenManagementSession.removeKeyPair(
                getAdmin(),
                getCurrentCryptoTokenId(),
                cryptoTokenKeyPairInfo.getAlias());
          } catch (Exception e) {
            super.addNonTranslatedErrorMessage(e.getMessage());
          }
        }
      }
    }
    flushCaches();
  }

  /**
   * @return A SlotList that contains the allowed slots numbers and indexes, or
   *     null if there's no such restriction
   */
  private SlotList getP11SlotList() {
    String library = currentCryptoToken.getP11Library();
    if (library == null) {
        return null;
    }
    WebConfiguration.P11LibraryInfo libinfo =
        WebConfiguration.getAvailableP11LibraryToAliasMap().get(library);
    if (libinfo == null) {
        return null;
    }
    return libinfo.getSlotList();
  }

  /**
   * @return true if we have checked and noticed that the P11 slot of the crypto
   *     token we try to create is the same as an already existing crypto token
   *     (including database protection tokens)
   */
  public boolean isP11SlotUsed() {
    return p11SlotUsed;
  }
}
