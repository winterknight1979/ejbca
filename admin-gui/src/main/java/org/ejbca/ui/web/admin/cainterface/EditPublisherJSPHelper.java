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

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.TreeSet;
import javax.faces.model.SelectItem;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.common.exception.ReferencesToItemExistException;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.publisher.ActiveDirectoryPublisher;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.CustomPublisherProperty;
import org.ejbca.core.model.ca.publisher.GeneralPurposeCustomPublisher;
import org.ejbca.core.model.ca.publisher.ICustomPublisher;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.ejbca.core.model.ca.publisher.LdapPublisher.ConnectionSecurity;
import org.ejbca.core.model.ca.publisher.LdapSearchPublisher;
import org.ejbca.core.model.ca.publisher.LegacyValidationAuthorityPublisher;
import org.ejbca.core.model.ca.publisher.MultiGroupPublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherDoesntExistsException;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;

/**
 * Contains help methods used to parse a publisher jsp page requests.
 *
 * @version $Id: EditPublisherJSPHelper.java 34119 2019-12-18 15:43:14Z aminkh $
 */
public class EditPublisherJSPHelper {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(EditPublisherJSPHelper.class);

  /** Param. */
  public static final String ACTION = "action";
  /** Param. */
  public static final String ACTION_EDIT_PUBLISHERS = "editpublishers";
  /** Param. */
  public static final String ACTION_EDIT_PUBLISHER = "editpublisher";

  /** Param. */
  public static final String ACTION_CHANGE_PUBLISHERTYPE =
      "changepublishertype";

  /** Param. */
  public static final String CHECKBOX_VALUE = BasePublisher.TRUE;

  //  Used in publishers.jsp
  /** Param. */
  public static final String BUTTON_EDIT_PUBLISHER = "buttoneditpublisher";
  /** Param. */
  public static final String BUTTON_DELETE_PUBLISHER = "buttondeletepublisher";
  /** Param. */
  public static final String BUTTON_ADD_PUBLISHER = "buttonaddpublisher";
  /** Param. */
  public static final String BUTTON_RENAME_PUBLISHER = "buttonrenamepublisher";
  /** Param. */
  public static final String BUTTON_CLONE_PUBLISHER = "buttonclonepublisher";

  /** Param. */
  public static final String SELECT_PUBLISHER = "selectpublisher";
  /** Param. */
  public static final String TEXTFIELD_PUBLISHERNAME = "textfieldpublishername";
  /** Param. */
  public static final String HIDDEN_PUBLISHERNAME = "hiddenpublishername";

  //  Buttons used in publisher.jsp
  /** Param. */
  public static final String BUTTON_TESTCONNECTION = "buttontestconnection";
  /** Param. */
  public static final String BUTTON_SAVE = "buttonsave";
  /** Param. */
  public static final String BUTTON_CANCEL = "buttoncancel";

  /** Param. */
  public static final String TYPE_CUSTOM = "typecustom";
  /** Param. */
  public static final String TYPE_LDAP = "typeldap";
  /** Param. */
  public static final String TYPE_AD = "typead";
  /** Param. */
  public static final String TYPE_LDAP_SEARCH = "typeldapsearch";

  /** Param. */
  public static final String HIDDEN_PUBLISHERTYPE = "hiddenpublishertype";
  /** Param. */
  public static final String SELECT_PUBLISHERTYPE = "selectpublishertype";

  /** Param. */
  public static final String SELECT_APPLICABLECAS = "selectapplicablecas";
  /** Param. */
  public static final String TEXTAREA_DESCRIPTION = "textareadescription";

  /** Param. */
  public static final String SELECT_CUSTOMCLASS = "selectcustomclass";
  /** Param. */
  public static final String TEXTFIELD_CUSTOMCLASSPATH =
      "textfieldcustomclasspath";
  /** Param. */
  public static final String TEXTAREA_CUSTOMPROPERTIES =
      "textareacustomproperties";
  /** Param. */
  public static final String TEXTAREA_PROPERTIES = "textareaproperties";
  /** Param. */
  public static final String TEXTAREA_GROUPS = "textareagroups";
  /** Param. */

  public static final String TEXTFIELD_LDAPHOSTNAME = "textfieldldaphostname";
  /** Param. */
  public static final String TEXTFIELD_LDAPPORT = "textfieldldapport";
  /** Param. */
  public static final String TEXTFIELD_LDAPBASEDN = "textfieldldapbasedn";
  /** Param. */
  public static final String TEXTFIELD_LDAPLOGINDN = "textfieldldaplogindn";
  /** Param. */
  public static final String TEXTFIELD_LDAPUSEROBJECTCLASS =
      "textfieldldapuserobjectclass";
  /** Param. */
  public static final String TEXTFIELD_LDAPCAOBJECTCLASS =
      "textfieldldapcaobjectclass";
  /** Param. */
  public static final String TEXTFIELD_LDAPUSERCERTATTRIBUTE =
      "textfieldldapusercertattribute";
  /** Param. */
  public static final String TEXTFIELD_LDAPCACERTATTRIBUTE =
      "textfieldldapcacertattribute";
  /** Param. */
  public static final String TEXTFIELD_LDAPCRLATTRIBUTE =
      "textfieldldapcrlattribute";
  /** Param. */
  public static final String TEXTFIELD_LDAPDELTACRLATTRIBUTE =
      "textfieldldapdeltacrlattribute";
  /** Param. */
  public static final String TEXTFIELD_LDAPARLATTRIBUTE =
      "textfieldldaparlattribute";
  /** Param. */
  public static final String TEXTFIELD_LDAPSEARCHBASEDN =
      "textfieldldapsearchbasedn";
  /** Param. */
  public static final String TEXTFIELD_LDAPSEARCHFILTER =
      "textfieldldapsearchfilter";
  /** Param. */
  public static final String TEXTFIELD_LDAPTIMEOUT = "textfieldldaptimeout";
  /** Param. */
  public static final String TEXTFIELD_LDAPREADTIMEOUT =
      "textfieldldapreadtimeout";
  /** Param. */
  public static final String TEXTFIELD_LDAPSTORETIMEOUT =
      "textfieldldapstoretimeout";
  /** Param. */
  public static final String TEXTFIELD_VA_DATASOURCE = "textfieldvadatasource";
  /** Param. */
  public static final String PASSWORD_LDAPLOGINPASSWORD =
      "textfieldldaploginpassword";
  /** Param. */
  public static final String PASSWORD_LDAPLOGINPASSWORDPLACEHOLDER =
      "placeholder";
  /** Param. */
  public static final String PASSWORD_LDAPCONFIRMLOGINPWD =
      "textfieldldaploginconfirmpwd";
  /** Param. */
  public static final String RADIO_LDAPCONNECTIONSECURITY =
      "radioldapconnectionsecurity";
  /** Param. */
  public static final String CHECKBOX_LDAPCREATENONEXISTING =
      "checkboxldapcreatenonexisting";
  /** Param. */
  public static final String CHECKBOX_LDAPMODIFYEXISTING =
      "checkboxldapmodifyexisting";
  /** Param. */
  public static final String CHECKBOX_LDAPMODIFYEXISTINGATTRIBUTES =
      "checkboxldapmodifyexistingattributes";
  /** Param. */
  public static final String CHECKBOX_LDAPADDNONEXISTING =
      "checkboxldapaddnonexisting";
  /** Param. */
  public static final String CHECKBOX_LDAP_CREATEINTERMEDIATENODES =
      "checkboxldapcreateintermediatenodes";
  /** Param. */
  public static final String CHECKBOX_LDAPADDMULTIPLECERTIFICATES =
      "checkboxaldapddmultiplecertificates";
  /** Param. */
  public static final String CHECKBOX_LDAP_REVOKE_REMOVECERTIFICATE =
      "checkboxldaprevokeremovecertificate";
  /** Param. */
  public static final String CHECKBOX_LDAP_REVOKE_REMOVEUSERONCERTREVOKE =
      "checkboxldaprevokeuseroncertrevoke";
  /** Param. */
  public static final String CHECKBOX_LDAP_SET_USERPASSWORD =
      "checkboxldapsetuserpassword";
  /** Param. */
  public static final String CHECKBOX_ONLYUSEQUEUE = "textfieldonlyusequeue";
  /** Param. */
  public static final String CHECKBOX_KEEPPUBLISHEDINQUEUE =
      "textfieldkeeppublishedinqueue";
  /** Param. */
  public static final String CHECKBOX_USEQUEUEFORCRLS =
      "textfieldusequeueforcrls";
  /** Param. */
  public static final String CHECKBOX_USEQUEUEFORCERTIFICATES =
      "textfieldusequeueforcertificates";
  /** Param. */
  public static final String CHECKBOX_VA_STORECERT = "textfieldvastorecert";
  /** Param. */
  public static final String CHECKBOX_VA_STORECRL = "textfieldvastorecrl";
  /** Param. */
  public static final String CHECKBOX_VA_ONLY_PUBLISH_REVOKED =
      "checkboxonlypublishrevoked";

  /** Param. */
  public static final String SELECT_LDAPUSEFIELDINLDAPDN =
      "selectldapusefieldsinldapdn";

  /** Param. */
  public static final String CHECKBOX_ADUSEPASSWORD = "checkboxadusepassword";
  /** Param. */
  public static final String SELECT_ADUSERACCOUNTCONTROL =
      "selectaduseraccountcontrol";
  /** Param. */
  public static final String SELECT_ADSAMACCOUNTNAME = "selectsamaccountname";
  /** Param. */
  public static final String TEXTFIELD_ADUSERDESCRIPTION =
      "textfieldaduserdescription";

  /** Param. */
  public static final String PAGE_PUBLISHER = "publisherpage.jspf";
  /** Param. */
  public static final String PAGE_PUBLISHERS = "publisherspage.jspf";

  /** Param. */
  private EjbcaWebBean ejbcawebbean;

  /** Param. */
  private CAInterfaceBean cabean;
  /** Param. */
  private boolean initialized = false;
  /** Param. */
  private boolean publisherexists = false;
  /** Param. */
  private boolean publisherdeletefailed = false;
  /** Param. */
  private String publisherDeleteFailedMessage = "";
  /** Param. */
  private boolean publisherEditFailed = false;
  /** Param. */
  private String publisherEditMessage = "";
  /** Param. */
  private boolean connectionmessage = false;
  /** Param. */
  private boolean connectionsuccessful = false;
  /** Param. */
  private String connectionerrormessage = "";
  /** Param. */
  private BasePublisher publisherdata = null;

  /** Param. */
  private String publishername = null;
  /** Param. */
  private Integer publisherId = null;

  /** Creates new LogInterfaceBean. */
  public EditPublisherJSPHelper() { }
  // Public methods.
  /**
   * Method that initialized the bean.
   *
   * @param request is a reference to the http request.
   * @param anejbcawebbean Web bean
   * @param acabean CA bean
   * @throws Exception Fail
   */
  public void initialize(
      final HttpServletRequest request,
      final EjbcaWebBean anejbcawebbean,
      final CAInterfaceBean acabean)
      throws Exception {

    if (!initialized) {
      this.cabean = acabean;
      this.ejbcawebbean = anejbcawebbean;
      initialized = true;
    }
  }

  /**
   * @param request Req
   * @return Req
   * @throws AuthorizationDeniedException Fail
   * @throws PublisherDoesntExistsException Fail
   * @throws PublisherExistsException Fail
   */
  @SuppressWarnings({"deprecation"})
  public String parseRequest(final HttpServletRequest request)
      throws AuthorizationDeniedException, PublisherDoesntExistsException,
          PublisherExistsException {
    String includefile = PAGE_PUBLISHERS;
    String publisher = null;
    PublisherDataHandler handler = cabean.getPublisherDataHandler();
    String action = null;

    try {
      RequestHelper.setDefaultCharacterEncoding(request);
    } catch (UnsupportedEncodingException e1) {
      // itgnore
    }
    action = request.getParameter(ACTION);
    if (action != null) {
      if (action.equals(ACTION_EDIT_PUBLISHERS)) {
        if (request.getParameter(BUTTON_EDIT_PUBLISHER) != null) {
          publisher = request.getParameter(SELECT_PUBLISHER);
          if (publisher != null) {
            if (!publisher.trim().equals("")) {
              includefile = PAGE_PUBLISHER;
              this.publishername = publisher;
              this.publisherdata = handler.getPublisher(publishername);
              this.publisherId = publisherdata.getPublisherId();
            } else {
              publisher = null;
            }
          }
          if (publisher == null) {
            includefile = PAGE_PUBLISHERS;
          }
        }
        if (request.getParameter(BUTTON_DELETE_PUBLISHER) != null) {
          publisher = request.getParameter(SELECT_PUBLISHER);
          if (publisher != null) {
            if (!publisher.trim().equals("")) {
              try {
                handler.removePublisher(publisher);
              } catch (ReferencesToItemExistException e) {
                setPublisherdeletefailed(true);
                setPublisherDeleteFailedMessage(e.getMessage());
              }
            }
          }
          includefile = PAGE_PUBLISHERS;
        }
        if (request.getParameter(BUTTON_RENAME_PUBLISHER) != null) {
          // Rename selected publisher and display profilespage.
          String newpublishername =
              request.getParameter(TEXTFIELD_PUBLISHERNAME);
          String oldpublishername = request.getParameter(SELECT_PUBLISHER);
          if (oldpublishername != null && newpublishername != null) {
            if (!newpublishername.trim().equals("")
                && !oldpublishername.trim().equals("")) {
              try {
                handler.renamePublisher(
                    oldpublishername.trim(), newpublishername.trim());
              } catch (PublisherExistsException e) {
                setPublisherexists(true);
              }
            }
          }
          includefile = PAGE_PUBLISHERS;
        }
        if (request.getParameter(BUTTON_ADD_PUBLISHER) != null) {
          publisher = request.getParameter(TEXTFIELD_PUBLISHERNAME);
          if (publisher != null) {
            if (!publisher.trim().equals("")) {
              try {
                handler.addPublisher(publisher.trim(), new LdapPublisher());
              } catch (PublisherExistsException e) {
                setPublisherexists(true);
              }
            }
          }
          includefile = PAGE_PUBLISHERS;
        }
        if (request.getParameter(BUTTON_CLONE_PUBLISHER) != null) {
          String newpublishername =
              request.getParameter(TEXTFIELD_PUBLISHERNAME);
          String oldpublishername = request.getParameter(SELECT_PUBLISHER);
          if (oldpublishername != null && newpublishername != null) {
            if (!newpublishername.trim().equals("")
                && !oldpublishername.trim().equals("")) {
              handler.clonePublisher(
                  oldpublishername.trim(), newpublishername.trim());
            }
          }
          includefile = PAGE_PUBLISHERS;
        }
      }
      if (action.equals(ACTION_EDIT_PUBLISHER)) {
        // Display edit access rules page.
        publisher = request.getParameter(HIDDEN_PUBLISHERNAME);
        this.publishername = publisher;
        if (publisher != null) {
          if (!publisher.trim().equals("")) {
            if (request.getParameter(BUTTON_SAVE) != null
                || request.getParameter(BUTTON_TESTCONNECTION) != null) {
              if (publisherdata == null) {
                int tokentype =
                    Integer.parseInt(
                        request.getParameter(HIDDEN_PUBLISHERTYPE));
                switch (tokentype) {
                  case PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER:
                    publisherdata = new CustomPublisherContainer();
                    break;
                  case PublisherConst.TYPE_LDAPPUBLISHER:
                    publisherdata = new LdapPublisher();
                    break;
                  case PublisherConst.TYPE_LDAPSEARCHPUBLISHER:
                    publisherdata = new LdapSearchPublisher();
                    break;
                  case PublisherConst.TYPE_ADPUBLISHER:
                    publisherdata = new ActiveDirectoryPublisher();
                    break;
                  case PublisherConst.TYPE_VAPUBLISHER:
                    publisherdata = null;
                    break;
                  case PublisherConst.TYPE_MULTIGROUPPUBLISHER:
                    publisherdata = new MultiGroupPublisher();
                    break;
                  default:
                    break;
                }
              }
              // Save changes.

              // General settings
              String value = request.getParameter(TEXTAREA_DESCRIPTION);
              if (value != null) {
                value = value.trim();
                publisherdata.setDescription(value);
              }
              value = request.getParameter(CHECKBOX_ONLYUSEQUEUE);
              publisherdata.setOnlyUseQueue(
                  value != null && value.equals(CHECKBOX_VALUE));
              value = request.getParameter(CHECKBOX_KEEPPUBLISHEDINQUEUE);
              publisherdata.setKeepPublishedInQueue(
                  value != null && value.equals(CHECKBOX_VALUE));
              value = request.getParameter(CHECKBOX_USEQUEUEFORCRLS);
              publisherdata.setUseQueueForCRLs(
                  value != null && value.equals(CHECKBOX_VALUE));
              value = request.getParameter(CHECKBOX_USEQUEUEFORCERTIFICATES);
              publisherdata.setUseQueueForCertificates(
                  value != null && value.equals(CHECKBOX_VALUE));

              if (publisherdata instanceof CustomPublisherContainer) {
                final CustomPublisherContainer custompublisherdata =
                    ((CustomPublisherContainer) publisherdata);
                String customClass =
                    request.getParameter(TEXTFIELD_CUSTOMCLASSPATH);
                String selectClass = request.getParameter(SELECT_CUSTOMCLASS);
                if (selectClass != null && !selectClass.isEmpty()) {
                  value = selectClass.trim();
                  custompublisherdata.setClassPath(value);
                } else if (customClass != null && !customClass.isEmpty()) {
                  value = customClass.trim();
                  custompublisherdata.setClassPath(value);
                } else {
                  // can happen if the user has Javascript turned off
                  throw new IllegalArgumentException("No class path selected");
                }
                if (custompublisherdata.isCustomUiRenderingSupported()) {
                  final StringBuilder sb = new StringBuilder();
                  for (final CustomPublisherProperty customPublisherProperty
                      : custompublisherdata.getCustomUiPropertyList(
                          this.cabean.getAuthenticationToken())) {
                    final String customValue =
                        request.getParameter(customPublisherProperty.getName());
                    if (customPublisherProperty.getType()
                        == CustomPublisherProperty.UI_BOOLEAN) {
                      if (customValue == null) {
                        sb.append(customPublisherProperty.getName())
                            .append('=')
                            .append("false")
                            .append('\n');
                      } else {
                        sb.append(customPublisherProperty.getName())
                            .append('=')
                            .append("true")
                            .append('\n');
                      }
                    } else {
                      if (customValue != null) {
                        sb.append(customPublisherProperty.getName())
                            .append('=')
                            .append(customValue)
                            .append('\n');
                      }
                    }
                  }
                  try {
                    custompublisherdata.setPropertyData(sb.toString());
                  } catch (PublisherException e) {
                    setPublisherEditFailed(true);
                    setPublisherEditMessage(e.getMessage());
                  }
                } else {
                  value = request.getParameter(TEXTAREA_CUSTOMPROPERTIES);
                  if (value != null) {
                    value = value.trim();
                    try {
                      custompublisherdata.setPropertyData(value);
                    } catch (PublisherException e) {
                      setPublisherEditFailed(true);
                      setPublisherEditMessage(e.getMessage());
                    }
                  }
                }
              }

              if (publisherdata instanceof LdapPublisher) {
                LdapPublisher ldappublisher = (LdapPublisher) publisherdata;

                value = request.getParameter(TEXTFIELD_LDAPHOSTNAME);
                if (value != null) {
                  value = value.trim();
                  ldappublisher.setHostnames(value);
                }
                value = request.getParameter(TEXTFIELD_LDAPPORT);
                if (value != null) {
                  value = value.trim();
                  ldappublisher.setPort(value);
                }
                value = request.getParameter(TEXTFIELD_LDAPBASEDN);
                if (value != null) {
                  value = value.trim();
                  ldappublisher.setBaseDN(value);
                }
                value = request.getParameter(TEXTFIELD_LDAPLOGINDN);
                if (value != null) {
                  value = value.trim();
                  ldappublisher.setLoginDN(value);
                }
                value = request.getParameter(PASSWORD_LDAPLOGINPASSWORD);
                if (value != null) {
                  value = value.trim();
                  // If we have a password that wasn't shown in the html page,
                  // and this wasn't changed by the user
                  // we will not edit the old password. This is a "security"
                  // feature so we don't send the actual password
                  // to be available in clear text in the users web browser
                  if (!PASSWORD_LDAPLOGINPASSWORDPLACEHOLDER.equals(value)) {
                    ldappublisher.setLoginPassword(value);
                  }
                }
                value = request.getParameter(TEXTFIELD_LDAPTIMEOUT);
                if (value != null) {
                  value = value.trim();
                  ldappublisher.setConnectionTimeOut(Integer.parseInt(value));
                }
                value = request.getParameter(TEXTFIELD_LDAPREADTIMEOUT);
                if (value != null) {
                  value = value.trim();
                  ldappublisher.setReadTimeOut(Integer.parseInt(value));
                }
                value = request.getParameter(TEXTFIELD_LDAPSTORETIMEOUT);
                if (value != null) {
                  value = value.trim();
                  ldappublisher.setStoreTimeOut(Integer.parseInt(value));
                }
                value = request.getParameter(TEXTFIELD_LDAPUSEROBJECTCLASS);
                if (value != null) {
                  value = value.trim();
                  ldappublisher.setUserObjectClass(value);
                }
                value = request.getParameter(TEXTFIELD_LDAPCAOBJECTCLASS);
                if (value != null) {
                  value = value.trim();
                  ldappublisher.setCAObjectClass(value);
                }
                value = request.getParameter(TEXTFIELD_LDAPUSERCERTATTRIBUTE);
                if (value != null) {
                  value = value.trim();
                  ldappublisher.setUserCertAttribute(value);
                }
                value = request.getParameter(TEXTFIELD_LDAPCACERTATTRIBUTE);
                if (value != null) {
                  value = value.trim();
                  ldappublisher.setCACertAttribute(value);
                }
                value = request.getParameter(TEXTFIELD_LDAPCRLATTRIBUTE);
                if (value != null) {
                  value = value.trim();
                  ldappublisher.setCRLAttribute(value);
                }
                value = request.getParameter(TEXTFIELD_LDAPDELTACRLATTRIBUTE);
                if (value != null) {
                  value = value.trim();
                  ldappublisher.setDeltaCRLAttribute(value);
                }
                value = request.getParameter(TEXTFIELD_LDAPARLATTRIBUTE);
                if (value != null) {
                  value = value.trim();
                  ldappublisher.setARLAttribute(value);
                }

                value = request.getParameter(RADIO_LDAPCONNECTIONSECURITY);
                if (value != null) {
                  ldappublisher.setConnectionSecurity(
                      ConnectionSecurity.valueOf(value));
                }

                value = request.getParameter(CHECKBOX_LDAPCREATENONEXISTING);
                if (value != null) {
                  ldappublisher.setCreateNonExistingUsers(
                      value.equals(CHECKBOX_VALUE));
                } else {
                  ldappublisher.setCreateNonExistingUsers(false);
                }
                value = request.getParameter(CHECKBOX_LDAPMODIFYEXISTING);
                if (value != null) {
                  ldappublisher.setModifyExistingUsers(
                      value.equals(CHECKBOX_VALUE));
                } else {
                  ldappublisher.setModifyExistingUsers(false);
                }
                value =
                    request.getParameter(CHECKBOX_LDAPMODIFYEXISTINGATTRIBUTES);
                if (value != null) {
                  ldappublisher.setModifyExistingAttributes(
                      value.equals(CHECKBOX_VALUE));
                } else {
                  ldappublisher.setModifyExistingAttributes(false);
                }
                value = request.getParameter(CHECKBOX_LDAPADDNONEXISTING);
                if (value != null) {
                  ldappublisher.setAddNonExistingAttributes(
                      value.equals(CHECKBOX_VALUE));
                } else {
                  ldappublisher.setAddNonExistingAttributes(false);
                }
                value =
                    request.getParameter(CHECKBOX_LDAP_CREATEINTERMEDIATENODES);
                if (value != null) {
                  ldappublisher.setCreateIntermediateNodes(
                      value.equals(CHECKBOX_VALUE));
                } else {
                  ldappublisher.setCreateIntermediateNodes(false);
                }
                value =
                    request.getParameter(CHECKBOX_LDAPADDMULTIPLECERTIFICATES);
                if (value != null) {
                  ldappublisher.setAddMultipleCertificates(
                      value.equals(CHECKBOX_VALUE));
                } else {
                  ldappublisher.setAddMultipleCertificates(false);
                }
                value =
                    request.getParameter(
                        CHECKBOX_LDAP_REVOKE_REMOVECERTIFICATE);
                if (value != null) {
                  ldappublisher.setRemoveRevokedCertificates(
                      value.equals(CHECKBOX_VALUE));
                } else {
                  ldappublisher.setRemoveRevokedCertificates(false);
                }
                value =
                    request.getParameter(
                        CHECKBOX_LDAP_REVOKE_REMOVEUSERONCERTREVOKE);
                if (value != null) {
                  ldappublisher.setRemoveUsersWhenCertRevoked(
                      value.equals(CHECKBOX_VALUE));
                } else {
                  ldappublisher.setRemoveUsersWhenCertRevoked(false);
                }
                value = request.getParameter(CHECKBOX_LDAP_SET_USERPASSWORD);
                if (value != null) {
                  ldappublisher.setUserPassword(value.equals(CHECKBOX_VALUE));
                } else {
                  ldappublisher.setUserPassword(false);
                }

                String[] values =
                    request.getParameterValues(SELECT_LDAPUSEFIELDINLDAPDN);
                if (values != null) {
                  ArrayList<Integer> usefields = new ArrayList<>();
                  for (int i = 0; i < values.length; i++) {
                    usefields.add(Integer.valueOf(values[i]));
                  }

                  ldappublisher.setUseFieldInLdapDN(usefields);
                }
              }

              if (publisherdata instanceof LdapSearchPublisher) {
                LdapSearchPublisher ldapsearchpublisher =
                    (LdapSearchPublisher) publisherdata;

                value = request.getParameter(TEXTFIELD_LDAPSEARCHBASEDN);
                if (value != null) {
                  value = value.trim();
                  ldapsearchpublisher.setSearchBaseDN(value);
                }
                value = request.getParameter(TEXTFIELD_LDAPSEARCHFILTER);
                if (value != null) {
                  value = value.trim();
                  ldapsearchpublisher.setSearchFilter(value);
                }
              }

              if (publisherdata instanceof ActiveDirectoryPublisher) {
                ActiveDirectoryPublisher adpublisher =
                    (ActiveDirectoryPublisher) publisherdata;

                value = request.getParameter(SELECT_ADSAMACCOUNTNAME);
                if (value != null) {
                  value = value.trim();
                  adpublisher.setSAMAccountName(Integer.parseInt(value));
                }

                value = request.getParameter(TEXTFIELD_ADUSERDESCRIPTION);
                if (value != null) {
                  value = value.trim();
                  adpublisher.setUserDescription(value);
                }

                value = request.getParameter(CHECKBOX_ADUSEPASSWORD);
                if (value != null) {
                  adpublisher.setUseUserPassword(value.equals(CHECKBOX_VALUE));
                } else {
                  adpublisher.setUseUserPassword(false);
                }
                value = request.getParameter(SELECT_ADUSERACCOUNTCONTROL);
                if (value != null) {
                  value = value.trim();
                  adpublisher.setUserAccountControl(Integer.parseInt(value));
                }
              }

              if (publisherdata instanceof MultiGroupPublisher) {
                MultiGroupPublisher multiGroupPublisher =
                    (MultiGroupPublisher) this.publisherdata;
                String groups = request.getParameter(TEXTAREA_GROUPS);
                HashMap<String, Integer> publisherNameToIdMap =
                    ejbcawebbean
                        .getEjb()
                        .getPublisherSession()
                        .getPublisherNameToIdMap();
                try {
                  List<TreeSet<Integer>> multiPublisherGroups =
                      convertMultiPublishersStringToData(
                          publisherNameToIdMap, groups);
                  multiGroupPublisher.setPublisherGroups(multiPublisherGroups);
                } catch (PublisherDoesntExistsException
                    | PublisherExistsException e) {
                  publisherEditFailed = true;
                  publisherEditMessage = e.getMessage();
                  return PAGE_PUBLISHER;
                }
              }

              if (request.getParameter(BUTTON_SAVE) != null) {
                handler.changePublisher(publisher, publisherdata);
                includefile = PAGE_PUBLISHERS;
              }
              if (request.getParameter(BUTTON_TESTCONNECTION) != null) {
                setConnectionmessage(true);
                handler.changePublisher(publisher, publisherdata);
                try {
                  handler.testConnection(publisher);
                  setConnectionsuccessful(true);
                } catch (PublisherConnectionException pce) {
                  setConnectionerrormessage(pce.getMessage());
                }
                includefile = PAGE_PUBLISHER;
              }
            }
            if (request.getParameter(BUTTON_CANCEL) != null) {
              // Don't save changes.
              includefile = PAGE_PUBLISHERS;
            }
          }
        }
      }

      if (action.equals(ACTION_CHANGE_PUBLISHERTYPE)) {
        this.publishername = request.getParameter(HIDDEN_PUBLISHERNAME);
        String value = request.getParameter(SELECT_PUBLISHERTYPE);
        if (value != null) {
          int dashPos = value.indexOf('-');
          if (dashPos == -1) {
            int profiletype = Integer.parseInt(value);
            switch (profiletype) {
              case PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER:
                publisherdata = new CustomPublisherContainer();
                break;
              case PublisherConst.TYPE_LDAPPUBLISHER:
                publisherdata = new LdapPublisher();
                break;
              case PublisherConst.TYPE_LDAPSEARCHPUBLISHER:
                publisherdata = new LdapSearchPublisher();
                break;
              case PublisherConst.TYPE_ADPUBLISHER:
                publisherdata = new ActiveDirectoryPublisher();
                break;
              case PublisherConst.TYPE_MULTIGROUPPUBLISHER:
                publisherdata = new MultiGroupPublisher();
                break;
              default: break;
            }
          } else {
            publisherdata = new CustomPublisherContainer();
            final String customClassName = value.substring(dashPos + 1);
            if (getCustomClasses().contains(customClassName)) {
              ((CustomPublisherContainer) publisherdata)
                  .setClassPath(customClassName);
            }
          }
        }

        includefile = PAGE_PUBLISHER;
      }
    }

    return includefile;
  }

  /**
   * Types.
   */
  private static final int[] AVAILABLEPUBLISHER_TYPES =
      new int[] {
        PublisherConst.TYPE_LDAPPUBLISHER,
        PublisherConst.TYPE_LDAPSEARCHPUBLISHER,
        PublisherConst.TYPE_ADPUBLISHER,
        PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER,
        PublisherConst.TYPE_MULTIGROUPPUBLISHER
      };
  /** Texts. */
  private static final String[] AVAILABLEPUBLISHER_TYPETEXTS =
      new String[] {
        "LDAPPUBLISHER",
        "LDAPSEARCHPUBLISHER",
        "ACTIVEDIRECTORYPUBLISHER",
        "CUSTOMPUBLISHER",
        "MULTIGROUPPUBLISHER"
      };

  /**
   * @return Name
   */
  public String getPublisherName() {
    return publishername;
  }

  /**
   * @return ID
   */
  public int getPublisherId() {
    return publisherId;
  }

  /**
   * @param className Class
   * @return Name
   */
  public String getPublisherName(final String className) {
    final String klassSimpleName =
        className.substring(className.lastIndexOf('.') + 1);
    // Present the publisher with a nice name if a language key is present
    String text = ejbcawebbean.getText(klassSimpleName.toUpperCase());
    if (text.equals(klassSimpleName.toUpperCase())) {
      // Present the publisher with the class name when no language key is
      // present
      final int len = 3;
      text =
          klassSimpleName
              + " ("
              + ejbcawebbean.getText(AVAILABLEPUBLISHER_TYPETEXTS[len])
              + ")";
    }
    return text;
  }

  /**
   * @return name
   */
  public String getCurrentPublisherName() {
    if (publisherdata instanceof CustomPublisherContainer) {
      ICustomPublisher iCustomPublisher =
          ((CustomPublisherContainer) publisherdata).getCustomPublisher();
      if (iCustomPublisher != null) {
        return getPublisherName(iCustomPublisher.getClass().getName());
      }
    }
    return getPublisherName(publisherdata.getClass().getName());
  }

  /**
   * @return the available publishers as list that can be used by JSF
   *     h:datatable in the future.
   */
  public List<SelectItem> getSelectablePublishers() {
    final List<SelectItem> ret = new ArrayList<>();
    // List all built in publisher types and all the dynamic ones
    for (int i = 0; i < AVAILABLEPUBLISHER_TYPES.length; i++) {
      final int type = AVAILABLEPUBLISHER_TYPES[i];
      if (type == PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER) {
        for (final String klass : getCustomClasses()) {
          ret.add(
              new SelectItem(
                  Integer.valueOf(type).toString() + "-" + klass,
                  getPublisherName(klass)));
        }
      } else {
        // Add built in publisher types
        ret.add(
            new SelectItem(
                Integer.valueOf(type).toString(),
                ejbcawebbean.getText(AVAILABLEPUBLISHER_TYPETEXTS[i])));
      }
    }
    // Allow selection of any class path
    final int len = 3;
    if (WebConfiguration.isManualClassPathsEnabled()) {
      ret.add(
          new SelectItem(
              Integer.valueOf(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER)
                  .toString(),
              ejbcawebbean.getText(AVAILABLEPUBLISHER_TYPETEXTS[len])));
    }
    // If an publisher was configured before the plugin mechanism we still want
    // to show it
    boolean customNoLongerAvailable = true;
    final String selectedPublisherValue = getSelectedPublisherValue();
    for (final SelectItem current : ret) {
      if (current.getValue().equals(selectedPublisherValue)) {
        customNoLongerAvailable = false;
        break;
      }
    }
    if (customNoLongerAvailable) {
      ret.add(
          new SelectItem(
              selectedPublisherValue, selectedPublisherValue.split("-")[1]));
    }
    // Sort by label
    Collections.sort(
        ret,
        new Comparator<SelectItem>() {
          @Override
          public int compare(
              final SelectItem selectItem0, final SelectItem selectItem1) {
            return String.valueOf(selectItem0.getLabel())
                .compareTo(String.valueOf(selectItem1.getLabel()));
          }
        });
    return ret;
  }

  /**
   * @return Value
   */
  public String getSelectedPublisherValue() {
    if (getPublisherType() == PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER) {
      final CustomPublisherContainer custompublisher =
          (CustomPublisherContainer) publisherdata;
      final String currentClass = custompublisher.getClassPath();
      if (currentClass == null || currentClass.isEmpty()) {
        return Integer.valueOf(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER)
            .toString();
      } else {
        return Integer.valueOf(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER)
                .toString()
            + "-"
            + currentClass;
      }
    }
    return Integer.valueOf(getPublisherType()).toString();
  }

  /**
   * @return type
   */
  @SuppressWarnings("deprecation")
  public int getPublisherType() {
    int retval = PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER;
    if (publisherdata instanceof CustomPublisherContainer) {
      retval = PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER;
    }
    if (publisherdata instanceof LdapPublisher) {
      retval = PublisherConst.TYPE_LDAPPUBLISHER;
    }
    if (publisherdata instanceof LdapSearchPublisher) {
      retval = PublisherConst.TYPE_LDAPSEARCHPUBLISHER;
    }
    // Legacy VA publisher doesn't exist in community edition, so check the
    // qualified class name instead.
    if (publisherdata
        .getClass()
        .getName()
        .equals(
            "org.ejbca.core.model.ca.publisher.ValidationAuthorityPublisher")) {
      retval = PublisherConst.TYPE_VAPUBLISHER;
    }
    if (publisherdata instanceof ActiveDirectoryPublisher) {
      retval = PublisherConst.TYPE_ADPUBLISHER;
    }
    if (publisherdata instanceof MultiGroupPublisher) {
      retval = PublisherConst.TYPE_MULTIGROUPPUBLISHER;
    }
    return retval;
  }

  /**
   * @return bool
   */
  public boolean hasEditRights() {
    return ejbcawebbean.isAuthorizedNoLogSilent(
        AccessRulesConstants.REGULAR_EDITPUBLISHER);
  }

  /** @return true if the publisher type is inherently read-only */
  public boolean isReadOnly() {
    if (!hasEditRights()) {
      return true;
    } else if (publisherdata instanceof CustomPublisherContainer) {
      ICustomPublisher pub =
          ((CustomPublisherContainer) publisherdata).getCustomPublisher();
      // Can be null if custom publisher has not been set up yet, then it has to
      // be editable
      return pub == null ? false : pub.isReadOnly();
    } else {
      return false;
    }
  }

  /** @return true if the publisher is deprecated and shouldn't be editable. */
  public boolean isDeprecated() {
    return publisherdata
        .getClass()
        .getName()
        .equals(
            LegacyValidationAuthorityPublisher
                .OLD_VA_PUBLISHER_QUALIFIED_NAME);
  }

  /**
   * @return len
   */
  public int getPublisherQueueLength() {
    return getPublisherQueueLength(publishername);
  }

  /**
   * @param intervalLower min
   * @param intervalUpper max
   * @return lenb
   */
  public int[] getPublisherQueueLength(
      final int[] intervalLower, final int[] intervalUpper) {
    return getPublisherQueueLength(publishername, intervalLower, intervalUpper);
  }

  /**
   * @param apublishername Name
   * @return len
   */
  @SuppressWarnings("deprecation")
  public int getPublisherQueueLength(final String apublishername) {
    return cabean.getPublisherQueueLength(
        cabean.getPublisherDataHandler().getPublisherId(apublishername));
  }

  /**
   * @param apublishername name
   * @param intervalLower min
   * @param intervalUpper max
   * @return len
   */
  @SuppressWarnings("deprecation")
  public int[] getPublisherQueueLength(
      final String apublishername,
      final int[] intervalLower,
      final int[] intervalUpper) {
    return cabean.getPublisherQueueLength(
        cabean.getPublisherDataHandler().getPublisherId(apublishername),
        intervalLower,
        intervalUpper);
  }

  /**
   * @return classes
   */
  public List<String> getCustomClasses() {
    final List<String> classes = new ArrayList<>();
    final ServiceLoader<ICustomPublisher> svcloader =
        ServiceLoader.load(ICustomPublisher.class);
    final boolean enabled =
        ((GlobalConfiguration)
                ejbcawebbean
                    .getEjb()
                    .getGlobalConfigurationSession()
                    .getCachedConfiguration(
                        GlobalConfiguration.GLOBAL_CONFIGURATION_ID))
            .getEnableExternalScripts();
    String name = null;
    for (ICustomPublisher implInstance : svcloader) {
      if (!implInstance.isReadOnly()) {
        name = implInstance.getClass().getName();
        if (enabled
            || !GeneralPurposeCustomPublisher.class.getName().equals(name)) {
          classes.add(name);
        }
      }
    }
    return classes;
  }

  /**
   * @return bool
   */
  public boolean isPublisherexists() {
    return publisherexists;
  }

  /**
   * @param apublisherexists bool
   */
  public void setPublisherexists(final boolean apublisherexists) {
    this.publisherexists = apublisherexists;
  }

  /**
   * @return Bool
   */
  public boolean isPublisherdeletefailed() {
    return publisherdeletefailed;
  }

  /**
   * @param apublisherdeletefailed bool
   */
  public void setPublisherdeletefailed(final boolean apublisherdeletefailed) {
    this.publisherdeletefailed = apublisherdeletefailed;
  }

  /**
   * @return msg
   */
  public String getPublisherDeleteFailedMessage() {
    return publisherDeleteFailedMessage;
  }

  /**
   * @param apublisherDeleteFailedMessage msg
   */
  public void setPublisherDeleteFailedMessage(
      final String apublisherDeleteFailedMessage) {
    this.publisherDeleteFailedMessage = apublisherDeleteFailedMessage;
  }

  /**
   * @return bool
   */
  public boolean isPublisherEditFailed() {
    return publisherEditFailed;
  }

  /**
   * @param apublisherEditFailed bool
   */
  public void setPublisherEditFailed(final boolean apublisherEditFailed) {
    this.publisherEditFailed = apublisherEditFailed;
  }

  /**
   * @return Msg
   */
  public String getPublisherEditMessage() {
    return publisherEditMessage;
  }

  /**
   * @param apublisherEditMessage msg
   */
  public void setPublisherEditMessage(final String apublisherEditMessage) {
    this.publisherEditMessage = apublisherEditMessage;
  }

  /**
   * @return msg
   */
  public boolean getConnectionmessage() {
    return connectionmessage;
  }

  /**
   * @param aconnectionmessage msg
   */
  public void setConnectionmessage(final boolean aconnectionmessage) {
    this.connectionmessage = aconnectionmessage;
  }

  /**
   * @return bool
   */
  public boolean isConnectionsuccessful() {
    return connectionsuccessful;
  }

  /**
   * @param isconnectionsuccessful bool
   */
  public void setConnectionsuccessful(final boolean isconnectionsuccessful) {
    this.connectionsuccessful = isconnectionsuccessful;
  }

  /**
   * @return msg
   */
  public String getConnectionerrormessage() {
    return connectionerrormessage;
  }

  /**
   * @param aconnectionerrormessage msg
   */
  public void setConnectionerrormessage(final String aconnectionerrormessage) {
    this.connectionerrormessage = aconnectionerrormessage;
  }

  /**
   * @return Data
   */
  public BasePublisher getPublisherdata() {
    return publisherdata;
  }

  /**
   * @param apublisherdata Data
   */
  public void setPublisherdata(final BasePublisher apublisherdata) {
    this.publisherdata = apublisherdata;
  }

  /**
   * @return password placeholder instead of real password in order to not send
   *     clear text password to browser, or empty string in case there is no
   *     ldap password (i.e. new publisher).
   */
  public String getPasswordPlaceholder() {
    if (this.publisherdata != null) {
      final String str =
          (String)
              this.publisherdata.getRawData().get(LdapPublisher.LOGINPASSWORD);
      if (StringUtils.isNotEmpty(str)) {
        return EditPublisherJSPHelper.PASSWORD_LDAPLOGINPASSWORDPLACEHOLDER;
      }
    }
    return "";
  }

  /**
   * @param publisherNameToIdMap Map
   * @param textareaData Data
   * @return Data
   * @throws PublisherDoesntExistsException fail
   * @throws PublisherExistsException fail
   */
  List<TreeSet<Integer>> convertMultiPublishersStringToData(
      final Map<String, Integer> publisherNameToIdMap,
      final String textareaData)
      throws PublisherDoesntExistsException, PublisherExistsException {
    TreeSet<Integer> selectedPublishers = new TreeSet<>();
    List<String> listOfPublisherNames = Arrays.asList(textareaData.split("\n"));
    ArrayList<TreeSet<Integer>> data = new ArrayList<>();
    TreeSet<Integer> tree = new TreeSet<>();
    for (String publisherName : listOfPublisherNames) {
      publisherName = publisherName.trim();
      if (StringUtils.isEmpty(publisherName)) {
        if (!tree.isEmpty()) {
          data.add(tree);
          tree = new TreeSet<>();
        }
      } else {
        Integer apublisherId = publisherNameToIdMap.get(publisherName);
        if (apublisherId != null) {
          if (!selectedPublishers.contains(apublisherId)) {
            tree.add(apublisherId);
            selectedPublishers.add(apublisherId);
          } else {
            throw new PublisherExistsException(
                "Publisher selected at least twice: " + publisherName);
          }
        } else {
          throw new PublisherDoesntExistsException(
              "Could not find publisher: \"" + publisherName + "\"");
        }
      }
    }
    if (!tree.isEmpty()) {
      data.add(tree);
    }
    return data;
  }

  /**
   * @param publisherIdToNameMap Name
   * @param data Data
   * @return Data
   */
  String convertMultiPublishersDataToString(
      final Map<Integer, String> publisherIdToNameMap,
      final List<TreeSet<Integer>> data) {
    StringBuffer result = new StringBuffer();
    String prefix = "";
    for (TreeSet<Integer> group : data) {
      List<String> publisherNames = new ArrayList<>();
      for (Integer apublisherId : group) {
        String name = publisherIdToNameMap.get(apublisherId);
        if (StringUtils.isNotEmpty(name)) {
          publisherNames.add(name);
        } else if (LOG.isDebugEnabled()) {
          LOG.info("No name found for publisher with id " + apublisherId);
        }
      }
      Collections.sort(publisherNames);
      for (String publisherName : publisherNames) {
        result.append(prefix);
        result.append(publisherName);
        prefix = "\n";
      }
      if (!publisherNames.isEmpty()) {
        result.append("\n");
      }
    }
    result.setLength(Math.max(result.length() - 1, 0));
    return result.toString();
  }

  /**
   * @return Data
   */
  public List<String> getPublisherListAvailable() {
    final List<String> ret = new ArrayList<>();
    final Collection<Integer> authorizedPublisherIds =
        ejbcawebbean
            .getEjb()
            .getCaAdminSession()
            .getAuthorizedPublisherIds(
                ejbcawebbean.getAdminObject(),
                Arrays.asList(PublisherConst.TYPE_MULTIGROUPPUBLISHER));
    authorizedPublisherIds.remove(this.publisherId);
    final Map<Integer, String> publisherIdToNameMap =
        ejbcawebbean.getEjb().getPublisherSession().getPublisherIdToNameMap();
    for (final Integer apublisherId : authorizedPublisherIds) {
      ret.add(publisherIdToNameMap.get(apublisherId));
    }
    Collections.sort(ret);
    return ret;
  }

  /**
   * @return Data
   */
  public String getMultiPublishersDataAsString() {
    MultiGroupPublisher multiGroupPublisher =
        (MultiGroupPublisher) this.publisherdata;
    final List<TreeSet<Integer>> publisherGroups =
        multiGroupPublisher.getPublisherGroups();
    final Map<Integer, String> publisherIdToNameMap =
        ejbcawebbean.getEjb().getPublisherSession().getPublisherIdToNameMap();
    return convertMultiPublishersDataToString(
        publisherIdToNameMap, publisherGroups);
  }
}
