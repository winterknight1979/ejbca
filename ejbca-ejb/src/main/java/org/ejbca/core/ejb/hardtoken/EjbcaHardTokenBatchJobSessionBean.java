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

package org.ejbca.core.ejb.hardtoken;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import org.apache.log4j.Logger;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.hardtoken.UnavailableTokenException;

/**
 * Used by hardtoken batch clients to retrieve users to generate from EJBCA RA.
 *
 * @version $Id: EjbcaHardTokenBatchJobSessionBean.java 27718 2018-01-03
 *     08:31:26Z mikekushner $
 */
@Stateless(
    mappedName =
        JndiConstants.APP_JNDI_PREFIX + "HardTokenBatchJobSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class EjbcaHardTokenBatchJobSessionBean
    implements HardTokenBatchJobSessionRemote, HardTokenBatchJobSessionLocal {

    /** Config. */
  public static final int MAX_RETURNED_QUEUE_SIZE = 300;

  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(EjbcaHardTokenBatchJobSessionBean.class);

  /** Internal localization of logs and errors. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();

  /** EM. */
  @PersistenceContext(unitName = "ejbca")
  private EntityManager entityManager;

  /** EJB. */
  @EJB private EndEntityAccessSessionLocal endEntityAccessSession;

  /** EJB. */
  @EJB private HardTokenSessionLocal hardTokenSession;

  @Override
  public EndEntityInformation getNextHardTokenToGenerate(final String alias)
      throws UnavailableTokenException {
    LOG.trace(">getNextHardTokenToGenerate()");
    EndEntityInformation returnval = null;
    if (LOG.isDebugEnabled()) {
      LOG.debug("alias=" + alias);
    }
    int hardTokenIssuerId = hardTokenSession.getHardTokenIssuerId(alias);
    if (LOG.isDebugEnabled()) {
      LOG.debug("hardTokenIssuerId=" + hardTokenIssuerId);
    }
    if (hardTokenIssuerId != HardTokenSessionBean.NO_ISSUER) {
      try {
        List<UserData> userDataList =
            endEntityAccessSession.findNewOrKeyrecByHardTokenIssuerId(
                hardTokenIssuerId, 0);
        if (!userDataList.isEmpty()) {
          returnval = userDataList.get(0).toEndEntityInformation();
          if (LOG.isDebugEnabled()) {
            LOG.debug("found user" + returnval.getUsername());
          }
          hardTokenSession.getIsHardTokenProfileAvailableToIssuer(
              hardTokenIssuerId, returnval);
          String msg =
              INTRES.getLocalizedMessage("hardtoken.userdatasent", alias);
          LOG.info(msg);
        }
      } catch (Exception e) {
        String msg =
            INTRES.getLocalizedMessage("hardtoken.errorsenduserdata", alias);
        LOG.info(msg, e);
        throw new EJBException(e);
      }
    }
    LOG.trace("<getNextHardTokenToGenerate()");
    return returnval;
  }

  @Override
  public Collection<EndEntityInformation> getNextHardTokensToGenerate(
      final String alias) throws UnavailableTokenException {
    LOG.trace(">getNextHardTokensToGenerate()");
    List<EndEntityInformation> returnval =
        new ArrayList<EndEntityInformation>();
    int hardTokenIssuerId = hardTokenSession.getHardTokenIssuerId(alias);
    if (hardTokenIssuerId != HardTokenSessionBean.NO_ISSUER) {
      try {
        List<UserData> userDataList =
            endEntityAccessSession.findNewOrKeyrecByHardTokenIssuerId(
                hardTokenIssuerId, MAX_RETURNED_QUEUE_SIZE);
        for (UserData userData : userDataList) {
          EndEntityInformation endEntityInformation =
              userData.toEndEntityInformation();
          hardTokenSession.getIsHardTokenProfileAvailableToIssuer(
              hardTokenIssuerId, endEntityInformation);
          returnval.add(endEntityInformation);
          String msg =
              INTRES.getLocalizedMessage("hardtoken.userdatasent", alias);
          LOG.info(msg);
        }
      } catch (Exception e) {
        String msg =
            INTRES.getLocalizedMessage("hardtoken.errorsenduserdata", alias);
        LOG.info(msg, e);
        throw new EJBException(e);
      }
    }
    if (returnval.size() == 0) {
      returnval = null;
    }
    LOG.trace("<getNextHardTokensToGenerate()");
    return returnval;
  }

  // TODO: Since there is no guarantee that the database query always will
  // return entries in the same order, this functionality might be broken!
  @Override
  public EndEntityInformation getNextHardTokenToGenerateInQueue(
      final String alias, final int index) throws UnavailableTokenException {
    LOG.trace(">getNextHardTokenToGenerateInQueue()");
    EndEntityInformation returnval = null;
    int hardTokenIssuerId = hardTokenSession.getHardTokenIssuerId(alias);
    if (hardTokenIssuerId != HardTokenSessionBean.NO_ISSUER) {
      try {
        List<UserData> userDataList =
            endEntityAccessSession.findNewOrKeyrecByHardTokenIssuerId(
                hardTokenIssuerId, 0);
        if (userDataList.size() > (index - 1)) {
          returnval = userDataList.get(index - 1).toEndEntityInformation();
          hardTokenSession.getIsHardTokenProfileAvailableToIssuer(
              hardTokenIssuerId, returnval);
          String msg =
              INTRES.getLocalizedMessage("hardtoken.userdatasent", alias);
          LOG.info(msg);
        }
      } catch (Exception e) {
        String msg =
            INTRES.getLocalizedMessage("hardtoken.errorsenduserdata", alias);
        LOG.info(msg, e);
        throw new EJBException(e);
      }
    }
    LOG.trace("<getNextHardTokenToGenerateInQueue()");
    return returnval;
  }

  @Override
  public int getNumberOfHardTokensToGenerate(final String alias) {
    LOG.trace(">getNumberOfHardTokensToGenerate()");
    long count = 0;
    int hardTokenIssuerId = hardTokenSession.getHardTokenIssuerId(alias);
    if (hardTokenIssuerId != HardTokenSessionBean.NO_ISSUER) {
      count =
          endEntityAccessSession.countNewOrKeyrecByHardTokenIssuerId(
              hardTokenIssuerId);
    }
    LOG.trace("<getNumberOfHardTokensToGenerate()");
    return (int) count;
  }

  @Override
  public boolean checkForHardTokenIssuerId(final int hardtokenissuerid) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">checkForHardTokenIssuerId(id: " + hardtokenissuerid + ")");
    }
    return endEntityAccessSession.countByHardTokenIssuerId(hardtokenissuerid)
        > 0;
  }
}
