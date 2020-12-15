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

package org.ejbca.core.ejb;

import javax.ejb.Local;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionLocal;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateCreateSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.CrlCreateSessionLocal;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keybind.InternalKeyBindingDataSessionLocal;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.keys.validation.KeyValidatorSessionLocal;
import org.cesecore.roles.management.RoleDataSessionLocal;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.roles.member.RoleMemberDataSessionLocal;
import org.cesecore.roles.member.RoleMemberSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.audit.EjbcaAuditorSessionLocal;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.authorization.AuthorizationSystemSessionLocal;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ca.store.CertReqHistorySessionLocal;
import org.ejbca.core.ejb.ca.validation.BlacklistSessionLocal;
import org.ejbca.core.ejb.crl.ImportCrlSessionLocal;
import org.ejbca.core.ejb.crl.PublishingCrlSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenBatchJobSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionLocal;
import org.ejbca.core.ejb.rest.EjbcaRestHelperSessionLocal;
import org.ejbca.core.ejb.services.ServiceSessionLocal;
import org.ejbca.core.ejb.upgrade.UpgradeSessionLocal;
import org.ejbca.core.ejb.ws.EjbcaWSHelperSessionLocal;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.era.RaMasterApiSessionLocal;
import org.ejbca.core.protocol.cmp.CmpMessageDispatcherSessionLocal;

/**
 * Due to the lack of standardization in JEE5 there is no way to lookup local
 * interfaces.
 *
 * <p>This Stateless Session Bean (SSB) act as a bridge between calling classes
 * in the same JVM, and the real ejb references.
 *
 * <p>This will allow us to define a single (this) local EJB in all web.xml and
 * ejb-jar.xml files and are then free to change and move around SSBs and their
 * interfaces without XML changes.
 *
 * @version $Id: EjbBridgeSessionLocal.java 29151 2018-06-07 15:11:05Z jeklund $
 */
@Local
public interface EjbBridgeSessionLocal {

      /**
       * Getter.
       * @return Session
       */
  AdminPreferenceSessionLocal getAdminPreferenceSession();

  /**
   * Getter.
   * @return Session
   */
  ApprovalExecutionSessionLocal getApprovalExecutionSession();

  /**
   * Getter.
   * @return Session
   */
  ApprovalProfileSessionLocal getApprovalProfileSession();

  /**
   * Getter.
   * @return Session
   */
  ApprovalSessionLocal getApprovalSession();

  /**
   * Getter.
   * @return Session
   */
  AuthorizationSessionLocal getAuthorizationSession();

  /**
   * Getter.
   * @return Session
   */
  AuthorizationSystemSessionLocal getAuthorizationSystemSession();

  /**
   * Getter.
   * @return Session
   */
  BlacklistSessionLocal getBlacklistSession();

  /**
   * Getter.
   * @return Session
   */
  CAAdminSessionLocal getCaAdminSession();

  /**
   * Getter.
   * @return Session
   */
  CaSessionLocal getCaSession();

  /**
   * Getter.
   * @return Session
   */
  CertificateCreateSessionLocal getCertificateCreateSession();

  /**
   * Getter.
   * @return Session
   */
  CertificateProfileSessionLocal getCertificateProfileSession();

  /**
   * Getter.
   * @return Session
   */
  CertificateStoreSessionLocal getCertificateStoreSession();

  /**
   * Getter.
   * @return Session
   */
  CertReqHistorySessionLocal getCertReqHistorySession();

  /**
   * Getter.
   * @return Session
   */
  CmpMessageDispatcherSessionLocal getCmpMessageDispatcherSession();

  /**
   * Getter.
   * @return Session
   */
  CrlCreateSessionLocal getCrlCreateSession();

  /**
   * Getter.
   * @return Session
   */
  CrlStoreSessionLocal getCrlStoreSession();

  /**
   * Getter.
   * @return Session
   */
  CryptoTokenManagementSessionLocal getCryptoTokenManagementSession();

  /**
   * Getter.
   * @return Session
   */
  CryptoTokenSessionLocal getCryptoTokenSession();

  /**
   * Getter.
   * @return Session
   */
  EjbcaAuditorSessionLocal getEjbcaAuditorSession();

  /**
   * Getter.
   * @return Session
   */
  EjbcaRestHelperSessionLocal getEjbcaRestHelperSession();

  /**
   * Getter.
   * @return Session
   */
  EjbcaWSHelperSessionLocal getEjbcaWSHelperSession();

  /**
   * Getter.
   * @return Session
   */
  EndEntityAccessSessionLocal getEndEntityAccessSession();

  /**
   * Getter.
   * @return Session
   */
  EndEntityAuthenticationSessionLocal getEndEntityAuthenticationSession();

  /**
   * Getter.
   * @return Session
   */
  EndEntityManagementSessionLocal getEndEntityManagementSession();

  /**
   * Getter.
   * @return Session
   */
  EndEntityProfileSessionLocal getEndEntityProfileSession();

  /**
   * Getter.
   * @return Session
   */
  GlobalConfigurationSessionLocal getGlobalConfigurationSession();

  /**
   * Getter.
   * @return Session
   */
  HardTokenBatchJobSessionLocal getHardTokenBatchJobSession();

  /**
   * Getter.
   * @return Session
   */
  HardTokenSessionLocal getHardTokenSession();

  /**
   * Getter.
   * @return Session
   */
  ImportCrlSessionLocal getImportCrlSession();

  /**
   * Getter.
   * @return Session
   */
  InternalKeyBindingDataSessionLocal getInternalKeyBindingDataSession();

  /**
   * Getter.
   * @return Session
   */
  InternalKeyBindingMgmtSessionLocal getInternalKeyBindingMgmtSession();

  /**
   * Getter.
   * @return Session
   */
  KeyRecoverySessionLocal getKeyRecoverySession();

  /**
   * Getter.
   * @return Session
   */
  KeyValidatorSessionLocal getKeyValidatorSession();

  /**
   * Getter.
   * @return Session
   */
  PublisherQueueSessionLocal getPublisherQueueSession();

  /**
   * Getter.
   * @return Session
   */
  PublisherSessionLocal getPublisherSession();

  /**
   * Getter.
   * @return Session
   */
  PublishingCrlSessionLocal getPublishingCrlSession();

  /**
   * Getter.
   * @return Session
   */
  RaMasterApiProxyBeanLocal getRaMasterApiProxyBean();

  /**
   * Getter.
   * @return Session
   */
  RaMasterApiSessionLocal getRaMasterApiSession();

  /**
   * Getter.
   * @return Session
   */
  RevocationSessionLocal getRevocationSession();

  /**
   * Getter.
   * @return Session
   */
  RoleDataSessionLocal getRoleDataSession();

  /**
   * Getter.
   * @return Session
   */
  RoleMemberDataSessionLocal getRoleMemberDataSession();

  /**
   * Getter.
   * @return Session
   */
  RoleMemberSessionLocal getRoleMemberSession();

  /**
   * Getter.
   * @return Session
   */
  RoleSessionLocal getRoleSession();

  /**
   * Getter.
   * @return Session
   */
  SecurityEventsAuditorSessionLocal getSecurityEventsAuditorSession();

  /**
   * Getter.
   * @return Session
   */
  SecurityEventsLoggerSessionLocal getSecurityEventsLoggerSession();

  /**
   * Getter.
   * @return Session
   */
  ServiceSessionLocal getServiceSession();

  /**
   * Getter.
   * @return Session
   */
  SignSessionLocal getSignSession();

  /**
   * Getter.
   * @return Session
   */
  UpgradeSessionLocal getUpgradeSession();

  /**
   * Getter.
   * @return Session
   */
  UserDataSourceSessionLocal getUserDataSourceSession();

  /**
   * Getter.
   * @return Session
   */
  WebAuthenticationProviderSessionLocal getWebAuthenticationProviderSession();
}
