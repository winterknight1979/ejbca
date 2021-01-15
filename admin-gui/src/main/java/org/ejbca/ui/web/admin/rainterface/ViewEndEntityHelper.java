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

package org.ejbca.ui.web.admin.rainterface;

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.TreeMap;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;

/**
 * Helper class for the View End Entity Page, parses the request and performs
 * appropriate actions.
 *
 * @version $Id: ViewEndEntityHelper.java 28844 2018-05-04 08:31:02Z samuellb $
 */
public class ViewEndEntityHelper implements Serializable {

  private static final long serialVersionUID = 7172234379584156296L;
  /** Param. */
  public static final String USER_PARAMETER = "username";
  /** Param. */
  public static final String TIMESTAMP_PARAMETER = "timestamp";
  /** Param. */

  public static final String BUTTON_CLOSE = "buttonclose";
  /** Param. */
  public static final String BUTTON_VIEW_NEWER = "buttonviewnewer";
  /** Param. */
  public static final String BUTTON_VIEW_OLDER = "buttonviewolder";
  /** Param. */

  public static final String ACTION = "action";
  /** Param. */
  public static final String ACTION_PAGE = "actionpage";
  /** Param. */

  public static final String HIDDEN_USERNAME = "hiddenusername";
  /** Param. */
  public static final String HIDDEN_INDEX = "hiddenindex";
  /** Param. */

  public static final String CHECKBOX_CLEARTEXTPASSWORD =
      "checkboxcleartextpassword";
  /** Param. */
  public static final String CHECKBOX_ADMINISTRATOR = "checkboxadministrator";
  /** Param. */
  public static final String CHECKBOX_KEYRECOVERABLE = "checkboxkeyrecoverable";
  /** Param. */
  public static final String CHECKBOX_SENDNOTIFICATION =
      "checkboxsendnotification";
  /** Param. */
  public static final String CHECKBOX_PRINT = "checkboxprint";

  /** Param. */
  public static final String TEXTFIELD_CARDNUMBER = "textfieldcardnumber";

  /** Param. */
  public static final String CHECKBOX_VALUE = "true";

  /** Param. */
  public static final int[] STATUSIDS = {
    EndEntityConstants.STATUS_NEW,
    EndEntityConstants.STATUS_FAILED,
    EndEntityConstants.STATUS_INITIALIZED,
    EndEntityConstants.STATUS_INPROCESS,
    EndEntityConstants.STATUS_GENERATED,
    EndEntityConstants.STATUS_REVOKED,
    EndEntityConstants.STATUS_HISTORICAL,
    EndEntityConstants.STATUS_KEYRECOVERY,
    EndEntityConstants.STATUS_WAITINGFORADDAPPROVAL
  };

  /** Param. */
  public static final String[] STATUSTEXTS = {
    "STATUSNEW",
    "STATUSFAILED",
    "STATUSINITIALIZED",
    "STATUSINPROCESS",
    "STATUSGENERATED",
    "STATUSREVOKED",
    "STATUSHISTORICAL",
    "STATUSKEYRECOVERY",
    "STATUSWAITINGFORADDAPPROVAL"
  };

  /** Param. */
  public static final int COLUMNWIDTH = 330;

  /** Param. */
  private boolean nouserparameter = true;
  /** Param. */
  private boolean notauthorized = false;
  /** Param. */
  private boolean profilenotfound = true;

  /** Param. */
  private UserView userdata = null;
  /** Param. */
  private UserView[] userdatas = null;
  /** Param. */
  private String username = null;
  /** Param. */
  private EndEntityProfile profile = null;
  /** Param. */
  private int[] fielddata = null;
  /** Param. */
  private String fieldvalue = null;

  /** Param. */
  private int row = 0;

  /** Param. */
  private int currentuserindex = 0;

  /** Param. */
  private String[] tokentexts = RAInterfaceBean.TOKENTEXTS;
  /** Param. */
  private int[] tokenids = RAInterfaceBean.TOKENIDS;

  /** Param. */
  private boolean initialized;

  /** Param. */
  private RAInterfaceBean rabean;
  /** Param. */
  private EjbcaWebBean ejbcawebbean;
  /** Param. */
  private CAInterfaceBean cabean;
  /** Param. */
  private final String currentusername = null;

  // Public methods.
  /**
   * Method that initialized the bean.
   *
   * @param anejbcawebbean bean
   * @param arabean bean
   * @param acabean bean
   * @throws Exception fail
   */
  public void initialize(
      final EjbcaWebBean anejbcawebbean,
      final RAInterfaceBean arabean,
      final CAInterfaceBean acabean)
      throws Exception {

    if (!initialized) {

      this.rabean = arabean;
      this.ejbcawebbean = anejbcawebbean;
      this.cabean = acabean;
      initialized = true;

      if (anejbcawebbean.getGlobalConfiguration().getIssueHardwareTokens()) {
        final TreeMap<String, Integer> hardtokenprofiles =
            anejbcawebbean.getHardTokenProfiles();
        tokentexts =
            new String
                [RAInterfaceBean.TOKENTEXTS.length
                    + hardtokenprofiles.keySet().size()];
        tokenids = new int[tokentexts.length];
        for (int i = 0; i < RAInterfaceBean.TOKENTEXTS.length; i++) {
          tokentexts[i] = RAInterfaceBean.TOKENTEXTS[i];
          tokenids[i] = RAInterfaceBean.TOKENIDS[i];
        }
        int index = 0;
        for (String name : hardtokenprofiles.keySet()) {
          tokentexts[index + RAInterfaceBean.TOKENTEXTS.length] = name;
          tokenids[index + RAInterfaceBean.TOKENTEXTS.length] =
              hardtokenprofiles.get(name).intValue();
          index++;
        }
      }
    }
  }

  /**
   * @param request req
   * @throws AuthorizationDeniedException fail
   * @throws Exception fail
   */
  public void parseRequest(final HttpServletRequest request)
      throws AuthorizationDeniedException, Exception {
    nouserparameter = true;
    notauthorized = false;
    profilenotfound = true;

    RequestHelper.setDefaultCharacterEncoding(request);
    String action = request.getParameter(ACTION);
    if (action == null
        && request.getParameter(TIMESTAMP_PARAMETER) != null
        && request.getParameter(USER_PARAMETER) != null) {
      username =
          java.net.URLDecoder.decode(
              request.getParameter(USER_PARAMETER), "UTF-8");
      Date timestamp =
          new Date(Long.parseLong(request.getParameter(TIMESTAMP_PARAMETER)));

      notauthorized = !getUserDatas(username);
      currentuserindex = this.getTimeStampIndex(timestamp);
      if (userdatas == null || userdatas.length < 1) {
        // Make sure possibly cached value is removed
        userdata = null;
        throw new ServletException("Could not find any history for this user.");
      }
      userdata = userdatas[currentuserindex];

      nouserparameter = false;
      if (userdata != null) {
        profile = rabean.getEndEntityProfile(userdata.getEndEntityProfileId());
      }
    } else {
      if (action == null && request.getParameter(USER_PARAMETER) != null) {
        username =
            java.net.URLDecoder.decode(
                request.getParameter(USER_PARAMETER), "UTF-8");
        notauthorized = !getUserDatas(username);
        nouserparameter = false;
        if ((userdatas != null) && (userdatas.length > 0)) {
          userdata = userdatas[0];
          currentuserindex = 0;
          if (userdata != null) {
            profile =
                rabean.getEndEntityProfile(userdata.getEndEntityProfileId());
          }
        } else {
          // Make sure possibly cached value is removed
          userdata = null;
        }
      } else {
        if (action != null && request.getParameter(USER_PARAMETER) != null) {
          username =
              java.net.URLDecoder.decode(
                  request.getParameter(USER_PARAMETER), "UTF-8");
          if (request.getParameter(BUTTON_VIEW_NEWER) != null) {
            if (currentuserindex > 0) {
              currentuserindex--;
            }
          }
          if (request.getParameter(BUTTON_VIEW_OLDER) != null) {
            if (currentuserindex + 1 < userdatas.length) {
              currentuserindex++;
            }
          }

          notauthorized = !getUserDatas(username);
          userdata = userdatas[currentuserindex];

          nouserparameter = false;
          if (userdata != null) {
            profile =
                rabean.getEndEntityProfile(userdata.getEndEntityProfileId());
          }
        }
      }
    }

    if (profile != null) {
      profilenotfound = false;
    }
  }

  /* returns false if the admin isn't authorized to view user
   * Sets the available userdatas of current and previous values
   */

  /**
   * @param ausername User
   * @return bool
   * @throws Exception fail
   */
  private boolean getUserDatas(final String ausername) throws Exception {
    boolean authorized = false;

    try {
      if (currentusername == null || !currentusername.equals(ausername)) {
        // fetch userdata and certreqdatas and order them by timestamp, newest
        // first.
        int currentexists = 0;
        UserView currentuser = rabean.findUser(ausername);
        if (currentuser != null) {
          currentexists = 1;
        }
        List<CertReqHistory> hist = cabean.getCertReqUserDatas(ausername);

        userdatas = new UserView[hist.size() + currentexists];

        if (currentuser != null) {
          userdatas[0] = currentuser;
        }
        for (int i = 0; i < hist.size(); i++) {
          CertReqHistory next = hist.get(i);
          userdatas[i + currentexists] =
              new UserView(
                  next.getEndEntityInformation(),
                  ejbcawebbean.getCAIdToNameMap());
        }
      }
      authorized = true;
    } catch (AuthorizationDeniedException e) {
    }
    return authorized;
  }

  /**
   * Returns an Index to the user that related to a certain timestamp.
   *
   * @param timestamp parameter sent from view log page
   * @return index in user datas that should be shown.
   */
  private int getTimeStampIndex(final Date timestamp) {
    int i;

    for (i = 0; i < userdatas.length; i++) {
      if (timestamp.after(userdatas[i].getTimeModified())
          || timestamp.equals(userdatas[i].getTimeModified())) {
        break;
      }
    }

    return i;
  }

/**
 * @return the nouserparameter
 */
public boolean isNouserparameter() {
    return nouserparameter;
}

/**
 * @param anouserparameter the nouserparameter to set
 */
public void setNouserparameter(final boolean anouserparameter) {
    this.nouserparameter = anouserparameter;
}

/**
 * @return the notauthorized
 */
public boolean isNotauthorized() {
    return notauthorized;
}

/**
 * @param anotauthorized the notauthorized to set
 */
public void setNotauthorized(final boolean anotauthorized) {
    this.notauthorized = anotauthorized;
}

/**
 * @return the profilenotfound
 */
public boolean isProfilenotfound() {
    return profilenotfound;
}

/**
 * @param aprofilenotfound the profilenotfound to set
 */
public void setProfilenotfound(final boolean aprofilenotfound) {
    this.profilenotfound = aprofilenotfound;
}

/**
 * @return the userdata
 */
public UserView getUserdata() {
    return userdata;
}

/**
 * @param theuserdata the userdata to set
 */
public void setUserdata(final UserView theuserdata) {
    this.userdata = theuserdata;
}

/**
 * @return the userdatas
 */
public UserView[] getUserdatas() {
    return userdatas;
}

/**
 * @param theuserdatas the userdatas to set
 */
public void setUserdatas(final UserView[] theuserdatas) {
    this.userdatas = theuserdatas;
}

/**
 * @return the username
 */
public String getUsername() {
    return username;
}

/**
 * @param ausername the username to set
 */
public void setUsername(final String ausername) {
    this.username = ausername;
}

/**
 * @return the profile
 */
public EndEntityProfile getProfile() {
    return profile;
}

/**
 * @param aprofile the profile to set
 */
public void setProfile(final EndEntityProfile aprofile) {
    this.profile = aprofile;
}

/**
 * @return the fielddata
 */
public int[] getFielddata() {
    return fielddata;
}

/**
 * @param thefielddata the fielddata to set
 */
public void setFielddata(final int[] thefielddata) {
    this.fielddata = thefielddata;
}

/**
 * @return the fieldvalue
 */
public String getFieldvalue() {
    return fieldvalue;
}

/**
 * @param afieldvalue the fieldvalue to set
 */
public void setFieldvalue(final String afieldvalue) {
    this.fieldvalue = afieldvalue;
}

/**
 * @return the row
 */
public int getRow() {
    return row;
}

/**
 * @param arow the row to set
 */
public void setRow(final int arow) {
    this.row = arow;
}

/**
 * @return the currentuserindex
 */
public int getCurrentuserindex() {
    return currentuserindex;
}

/**
 * @param acurrentuserindex the currentuserindex to set
 */
public void setCurrentuserindex(final int acurrentuserindex) {
    this.currentuserindex = acurrentuserindex;
}

/**
 * @return the tokentexts
 */
public String[] getTokentexts() {
    return tokentexts;
}

/**
 * @param thetokentexts the tokentexts to set
 */
public void setTokentexts(final String[] thetokentexts) {
    this.tokentexts = thetokentexts;
}

/**
 * @return the tokenids
 */
public int[] getTokenids() {
    return tokenids;
}

/**
 * @param thetokenids the tokenids to set
 */
public void setTokenids(final int[] thetokenids) {
    this.tokenids = thetokenids;
}
}
