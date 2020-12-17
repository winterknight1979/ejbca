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

package org.ejbca.core.protocol.acme;

import java.util.List;
import java.util.Set;
import javax.ejb.Local;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * Proxy for identifying all calls that are needed in the RaMasterApi to fully
 * support ACME.
 *
 * @version $Id: AcmeRaMasterApiSessionLocal.java 29784 2018-08-30 08:20:30Z
 *     tarmo_r_helmes $
 */
@Local
public interface AcmeRaMasterApiSessionLocal {

  /**
   * @param authenticationToken token
   * @param fingerprint FVP
   * @param newStatus Status
   * @param revocationReason Reason
   * @return Success
   * @throws ApprovalException Fail
   * @throws WaitingForApprovalException Fail
   * @see
   *     org.ejbca.core.model.era.RaMasterApi#changeCertificateStatus(AuthenticationToken,
   *     String, int, int)
   */
  boolean changeCertificateStatus(
      AuthenticationToken authenticationToken,
      String fingerprint,
      int newStatus,
      int revocationReason)
      throws ApprovalException, WaitingForApprovalException;

  /**
   * @param authenticationToken Token
   * @param fingerprint FP
   * @return CDW
   * @see
   *     org.ejbca.core.model.era.RaMasterApi#searchForCertificate(AuthenticationToken,
   *     String)
   */
  CertificateDataWrapper searchForCertificate(
      AuthenticationToken authenticationToken, String fingerprint);

  /**
   * @param accountId ID
   * @return Account see
   *     org.ejbca.core.protocol.acme.AcmeAccountDataSessionBean#getAcmeAccount(String)
   */
  AcmeAccount getAcmeAccount(String accountId);

  /**
   * see
   * org.ejbca.core.protocol.acme.AcmeAccountDataSessionBean#getAcmeAccountByPublicKeyStorageId(String).
   *
   * @param publicKeyStorageId ID
   * @return Account
   */
  AcmeAccount getAcmeAccountByPublicKeyStorageId(String publicKeyStorageId);

  /**
   * see
   * org.ejbca.core.protocol.acme.AcmeAccountDataSessionBean#createOrUpdate(AcmeAccount).
   *
   * @param acmeAccount Account
   * @return Persisted
   */
  String persistAcmeAccountData(AcmeAccount acmeAccount);

  /**
   * see
   * org.ejbca.ui.web.protocol.acme.storage.AcmeOrderDataSessionBean#getAcmeOrderById(String).
   *
   * @param orderId ID
   * @return Order
   */
  AcmeOrder getAcmeOrder(String orderId);

  /**
   * see
   * org.ejbca.ui.web.protocol.acme.storage.AcmeOrderDataSessionBean#getAcmeOrdersByAccountId(String).
   *
   * @param accountId ID
   * @return Orders
   */
  Set<AcmeOrder> getAcmeOrdersByAccountId(String accountId);

  /**
   * see
   * org.ejbca.ui.web.protocol.acme.storage.AcmeOrderDataSessionBean#getFinalizedAcmeOrdersByFingerprint(String).
   *
   * @param fingerprint FP
   * @return Orders
   */
  Set<AcmeOrder> getFinalizedAcmeOrdersByFingerprint(String fingerprint);

  /**
   * see
   * org.ejbca.ui.web.protocol.acme.storage.AcmeOrderDataSessionBean#persist(AcmeOrder).
   *
   * @param acmeOrder Order
   * @return Persisted
   */
  String persistAcmeOrderData(AcmeOrder acmeOrder);

  /**
   * see
   * org.ejbca.ui.web.protocol.acme.storage.AcmeOrderDataSessionBean#persist.
   *
   * @param acmeOrders Orders
   * @return persist
   */
  List<String> persistAcmeOrderData(List<AcmeOrder> acmeOrders);

  /**
   * see
   * org.ejbca.ui.web.protocol.acme.storage.AcmeOrderDataSessionBean#remove(String).
   *
   * @param orderId ID
   */
  void removeAcmeOrder(String orderId);

  /**
   * see
   * org.ejbca.ui.web.protocol.acme.storage.AcmeOrderDataSessionBean#removeAll(List&lt;String&gt;).
   *
   * @param orderId IDs
   */
  void removeAcmeOrders(List<String> orderId);

  /**
   * see
   * org.ejbca.core.protocol.acme.AcmeAuthorizationDataSessionBean#getAcmeAuthorization(String).
   *
   * @param authorizationId ID
   * @return Auth
   */
  AcmeAuthorization getAcmeAuthorizationById(String authorizationId);

  /**
   * see
   * org.ejbca.core.protocol.acme.AcmeAuthorizationDataSessionBean#getAcmeAuthorizationsByOrderId(String).
   *
   * @param orderId ID
   * @return Auths
   */
  List<AcmeAuthorization> getAcmeAuthorizationsByOrderId(String orderId);

  /**
   * see
   * org.ejbca.core.protocol.acme.AcmeAuthorizationDataSessionBean#getAcmeAuthorizationsByAccountId(String).
   *
   * @param accountId ID
   * @return Auths
   */
  List<AcmeAuthorization> getAcmeAuthorizationsByAccountId(String accountId);

  /**
   * see
   * org.ejbca.core.protocol.acme.AcmeAuthorizationDataSessionBean#createOrUpdate(AcmeAuthorization).
   *
   * @param acmeAuthorization Auth
   * @return Persisted
   */
  String persistAcmeAuthorizationData(AcmeAuthorization acmeAuthorization);

  /**
   * see
   * org.ejbca.core.protocol.acme.AcmeAuthorizationDataSessionBean#createOrUpdateList(List).
   *
   * @param acmeAuthorizations Auths
   */
  void persistAcmeAuthorizationDataList(
      List<AcmeAuthorization> acmeAuthorizations);

  /**
   * see
   * org.ejbca.core.protocol.acme.AcmeChallengeDataSessionBean#getAcmeChallenge(String).
   *
   * @param challengeId ID
   * @return Challenge
   */
  AcmeChallenge getAcmeChallengeById(String challengeId);

  /**
   * see
   * org.ejbca.core.protocol.acme.AcmeChallengeDataSessionBean#getAcmeChallengesByAuthorizationId(String).
   *
   * @param authorizationId ID
   * @return Challenges
   */
  List<AcmeChallenge> getAcmeChallengesByAuthorizationId(
      String authorizationId);

  /**
   * see
   * org.ejbca.core.protocol.acme.AcmeChallengeDataSessionBean#createOrUpdate(AcmeChallenge).
   *
   * @param acmeChallenge Challenge
   */
  void persistAcmeChallengeData(AcmeChallenge acmeChallenge);

  /**
   * see
   * org.ejbca.core.protocol.acme.AcmeChallengeDataSessionBean#createOrUpdateList(List).
   *
   * @param acmeChallenges Challenges
   */
  void persistAcmeChallengeDataList(List<AcmeChallenge> acmeChallenges);

  /**
   * see org.ejbca.core.protocol.acme.AcmeNonceDataSessionBean#useNonce(String,
   * long, long).
   *
   * @param nonce Nonce
   * @param timeCreated Creation
   * @param timeExpires Expirt
   * @return success
   */
  boolean useAcmeReplayNonce(String nonce, long timeCreated, long timeExpires);

  /**
   * @param authenticationToken Token
   * @param endEntityAccessRule Rule
   * @return IDs
   * @see
   *     org.ejbca.core.model.era.RaMasterApi#getAuthorizedEndEntityProfiles(AuthenticationToken,
   *     String)
   */
  IdNameHashMap<EndEntityProfile> getAuthorizedEndEntityProfiles(
      AuthenticationToken authenticationToken, String endEntityAccessRule);

  /**
   * @param authenticationToken Token
   * @return IDs
   * @see
   *     org.ejbca.core.model.era.RaMasterApi#getAuthorizedCertificateProfiles(AuthenticationToken)
   */
  IdNameHashMap<CertificateProfile> getAuthorizedCertificateProfiles(
      AuthenticationToken authenticationToken);

  /**
   * @param authenticationToken Token
   * @return IDs
   * @see
   *     org.ejbca.core.model.era.RaMasterApi#getAuthorizedCAInfos(AuthenticationToken)
   */
  IdNameHashMap<CAInfo> getAuthorizedCAInfos(
      AuthenticationToken authenticationToken);

  /**
   * see org.ejbca.core.model.era.RaMasterApi#searchUser(AuthenticationToken,
   * String).
   *
   * @param authenticationToken Token
   * @param username User
   * @return Info
   */
  EndEntityInformation searchUser(
      AuthenticationToken authenticationToken, String username);

  /**
   * @param authenticationToken Token
   * @param endEntityInformation Entity
   * @param clearpwd PWD
   * @throws AuthorizationDeniedException Fail
   * @throws EjbcaException Fail
   * @throws WaitingForApprovalException Fail
   * @see org.ejbca.core.model.era.RaMasterApi#addUser(AuthenticationToken,
   *     EndEntityInformation, boolean)
   */
  void addUser(
      AuthenticationToken authenticationToken,
      EndEntityInformation endEntityInformation,
      boolean clearpwd)
      throws AuthorizationDeniedException, EjbcaException,
          WaitingForApprovalException;

  /**
   * @param authenticationToken Token
   * @param endEntityInformation Info
   * @return Cert
   * @throws AuthorizationDeniedException Fail
   * @throws EjbcaException Fail
   * @see
   *     org.ejbca.core.model.era.RaMasterApi#createCertificate(AuthenticationToken,
   *     EndEntityInformation)
   */
  byte[] createCertificate(
      AuthenticationToken authenticationToken,
      EndEntityInformation endEntityInformation)
      throws AuthorizationDeniedException, EjbcaException;

  /**
   * @param authenticationToken Auth
   * @param caId CA
   * @return IDs
   * @throws CADoesntExistsException Fail
   * @throws AuthorizationDeniedException Fail
   * @see
   *     org.ejbca.core.model.era.RaMasterApi#getCaaIdentities(AuthenticationToken,
   *     int)
   */
  Set<String> getCaaIdentities(
      AuthenticationToken authenticationToken, int caId)
      throws CADoesntExistsException, AuthorizationDeniedException;

  /**
   * @return bool
   */
  boolean isPeerAuthorizedAcme();
}
