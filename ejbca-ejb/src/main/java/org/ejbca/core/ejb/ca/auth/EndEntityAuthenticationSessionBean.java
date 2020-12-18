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

package org.ejbca.core.ejb.ca.auth;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import org.apache.log4j.Logger;
import org.cesecore.ErrorCode;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;

/**
 * Authenticates users towards a user database.
 *
 * @see EndEntityAuthenticationSession
 * @version $Id: EndEntityAuthenticationSessionBean.java 33852 2019-11-14
 *     13:27:03Z jekaterina_b_helmes $
 */
@Stateless(
    mappedName =
        JndiConstants.APP_JNDI_PREFIX + "EndEntityAuthenticationSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class EndEntityAuthenticationSessionBean
    implements EndEntityAuthenticationSessionLocal,
        EndEntityAuthenticationSessionRemote {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(EndEntityAuthenticationSessionBean.class);

  /** EM. */
  @PersistenceContext(unitName = "ejbca")
  private EntityManager entityManager;

  /** EJB. */
  @EJB private EndEntityAccessSessionLocal endEntityAccessSession;
  /** EJB. */
  @EJB private EndEntityManagementSessionLocal endEntityManagementSession;
  /** EJB. */
  @EJB private SecurityEventsLoggerSessionLocal auditSession;

  /** Internal localization of logs and errors. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();

  @Override
  public EndEntityInformation authenticateUser(
      final AuthenticationToken admin,
      final String username,
      final String password)
      throws AuthStatusException, AuthLoginException, NoSuchEndEntityException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">authenticateUser(" + username + ", hiddenpwd)");
    }
    boolean eichange = false;
    try {
      // Find the user with username username, or throw ObjectNotFoundException
      final UserData data = endEntityAccessSession.findByUsername(username);
      if (data == null) {
        throw new NoSuchEndEntityException(
            "Could not find username " + username);
      }
      // Decrease the remaining login attempts. When zero, the status is set to
      // STATUS_GENERATED
      ExtendedInformation ei = data.getExtendedInformation();
      eichange =
          EndEntityAuthenticationSessionBean.decRemainingLoginAttempts(
              data, ei);
      boolean authenticated = false;
      final int status = data.getStatus();
      if ((status == EndEntityConstants.STATUS_NEW)
          || (status == EndEntityConstants.STATUS_FAILED)
          || (status == EndEntityConstants.STATUS_INPROCESS)
          || (status == EndEntityConstants.STATUS_KEYRECOVERY)) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Trying to authenticate user: username="
                  + username
                  + ", dn="
                  + data.getSubjectDnNeverNull()
                  + ", email="
                  + data.getSubjectEmail()
                  + ", status="
                  + status
                  + ", type="
                  + data.getType());
        }
        if (!data.comparePassword(password)) {
          final String msg =
              INTRES.getLocalizedMessage("authentication.invalidpwd", username);
          final Map<String, Object> details = new LinkedHashMap<>();
          details.put("msg", msg);
          auditSession.log(
              EjbcaEventTypes.CA_USERAUTH,
              EventStatus.FAILURE,
              ModuleTypes.CA,
              EjbcaServiceTypes.EJBCA,
              admin.toString(),
              String.valueOf(data.getCaId()),
              null,
              username,
              details);
          if (eichange) {
            data.setTimeModified(new Date().getTime());
            data.setExtendedInformation(ei);
          }
          throw new AuthLoginException(ErrorCode.LOGIN_ERROR, msg);
        }
        // Resets the remaining login attempts as this was a successful login
        if (UserData.resetRemainingLoginAttemptsInternal(
            ei, data.getUsername())) {
          // This call can never set eichange to false, only to true (because it
          // is already false if it should be)
          eichange = true;
        }
        // Log formal message that authentication was successful
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put(
            "msg",
            INTRES.getLocalizedMessage("authentication.authok", username));
        auditSession.log(
            EjbcaEventTypes.CA_USERAUTH,
            EventStatus.SUCCESS,
            ModuleTypes.CA,
            EjbcaServiceTypes.EJBCA,
            admin.toString(),
            String.valueOf(data.getCaId()),
            null,
            username,
            details);
        if (LOG.isTraceEnabled()) {
          LOG.trace("<authenticateUser(" + username + ", hiddenpwd)");
        }
        authenticated = true;
      }
      if (eichange) {
        data.setTimeModified(new Date().getTime());
        data.setExtendedInformation(ei);
      }
      if (authenticated) {
        return data.toEndEntityInformation();
      } else {
        final String msg =
            INTRES.getLocalizedMessage(
                "authentication.wrongstatus",
                EndEntityConstants.getStatusText(status),
                status,
                username);
        LOG.info(msg);
        throw new AuthStatusException(msg);
      }
    } catch (NoSuchEndEntityException oe) {
      final String msg =
          INTRES.getLocalizedMessage("authentication.usernotfound", username);
      LOG.info(msg);
      throw oe;
    } catch (AuthStatusException | AuthLoginException se) {
      throw se;
    } catch (Exception e) {
      LOG.error(INTRES.getLocalizedMessage("error.unknown"), e);
      throw new EJBException(e);
    }
  }

  /**
   * Decrements the remaining failed login attempts counter. If the counter
   * already was zero the status for the user is set to {@link
   * EndEntityConstants#STATUS_GENERATED} if it wasn't that already. This method
   * does nothing if the counter value is set to UNLIMITED (-1).
   *
   * @param ei Info
   * @param user the unique username of the user
   * @return true if the value was decremented or the status was changed, false
   *     if not
   */
  public static boolean decRemainingLoginAttempts(
      final UserData user, final ExtendedInformation ei) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">decRemainingLoginAttempts(" + user.getUsername() + ")");
    }
    boolean ret = false;
    int counter = Integer.MAX_VALUE;
    if (ei != null) {
      counter = ei.getRemainingLoginAttempts();
      // If we get to 0 we must set status to generated
      if (counter == 0) {
        // if it isn't already
        if (user.getStatus() != EndEntityConstants.STATUS_GENERATED) {
          user.setStatus(EndEntityConstants.STATUS_GENERATED);
          user.setTimeModified(new Date().getTime());
          if (UserData.resetRemainingLoginAttemptsInternal(
              ei, user.getUsername())) {
            final String msg =
                INTRES.getLocalizedMessage(
                    "ra.decreasedloginattemptscounter",
                    user.getUsername(),
                    counter);
            LOG.info(msg);
            // We return that ei was changed so it can be persisted later
            ret = true;
          }
        }
      } else if (counter != -1) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Found a remaining login counter with value " + counter);
        }
        ei.setRemainingLoginAttempts(--counter);
        // We return ei to set later
        // We return that ei was changed so it can be persisted later
        ret = true;
        String msg =
            INTRES.getLocalizedMessage(
                "ra.decreasedloginattemptscounter",
                user.getUsername(),
                counter);
        LOG.info(msg);
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Found a remaining login counter with value UNLIMITED, not"
                  + " decreased in db.");
        }
        counter = Integer.MAX_VALUE;
      }
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          "<decRemainingLoginAttempts(" + user.getUsername() + "): " + counter);
    }
    return ret;
  }

  @Override
  public void finishUser(final EndEntityInformation data)
      throws NoSuchEndEntityException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">finishUser(" + data.getUsername() + ", hiddenpwd)");
    }
    try {

      // See if we are allowed for make more requests than this one. If not user
      // status changed by decRequestCounter
      final int counter =
          endEntityManagementSession.decRequestCounter(data.getUsername());
      if (counter <= 0) {
        LOG.info(
            INTRES.getLocalizedMessage(
                "authentication.statuschanged", data.getUsername()));
      }
      if (LOG.isTraceEnabled()) {
        LOG.trace("<finishUser(" + data.getUsername() + ", hiddenpwd)");
      }
    } catch (NoSuchEndEntityException e) {
      final String msg =
          INTRES.getLocalizedMessage(
              "authentication.usernotfound", data.getUsername());
      LOG.info(msg);
      throw new NoSuchEndEntityException(e.getMessage());
    } catch (ApprovalException | WaitingForApprovalException e) {
      // Should never happen
      LOG.error("ApprovalException: ", e);
      throw new EJBException(e);
    }
  }
}
