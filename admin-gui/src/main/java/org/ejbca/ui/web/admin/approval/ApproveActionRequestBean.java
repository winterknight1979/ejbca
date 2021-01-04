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

package org.ejbca.ui.web.admin.approval;

import javax.faces.application.Application;
import javax.faces.context.FacesContext;
import javax.servlet.http.HttpServletRequest;

/**
 * Bean to set the right Approve Request Data when calling the approveaction.jsf
 * page from javascript
 *
 * @version $Id: ApproveActionRequestBean.java 28844 2018-05-04 08:31:02Z
 *     samuellb $
 */
public class ApproveActionRequestBean {
  private int uniqueId;

  public ApproveActionRequestBean() {
    FacesContext ctx = FacesContext.getCurrentInstance();

    try {
      String param =
          ((HttpServletRequest) ctx.getExternalContext().getRequest())
              .getParameter("uniqueId");
      if (param != null) {
        uniqueId =
            Integer.parseInt(
                ((HttpServletRequest) ctx.getExternalContext().getRequest())
                    .getParameter("uniqueId"));
        Application app = ctx.getApplication();
        ApproveActionManagedBean value =
            app.evaluateExpressionGet(
                ctx,
                "#{approvalActionManagedBean}",
                ApproveActionManagedBean.class);
        value.setUniqueId(uniqueId);
        value.updateApprovalRequest(uniqueId);
      }
    } catch (NumberFormatException e) {

    }
  }

  public int getUniqueId() {
    return uniqueId;
  }

  public void setUniqueId(final int uniqueId) {
    this.uniqueId = uniqueId;
  }
}
