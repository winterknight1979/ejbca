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

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
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
 * @version $Id: EjbBridgeSessionBean.java 29151 2018-06-07 15:11:05Z jeklund $
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class EjbBridgeSessionBean implements EjbBridgeSessionLocal {

      /** EJB. */
  @EJB private AdminPreferenceSessionLocal adminPreferenceSession;
  /** EJB. */
  @EJB private ApprovalExecutionSessionLocal approvalExecutionSession;
  /** EJB. */
  @EJB private ApprovalProfileSessionLocal approvalProfileSession;
  /** EJB. */
  @EJB private ApprovalSessionLocal approvalSession;
  /** EJB. */
  @EJB private AuthorizationSessionLocal authorizationSession;
  /** EJB. */
  @EJB private AuthorizationSystemSessionLocal authorizationSystemSession;
  /** EJB. */
  @EJB private BlacklistSessionLocal blacklistSession;
  /** EJB. */
  @EJB private CAAdminSessionLocal caAdminSession;
  /** EJB. */
  @EJB private CaSessionLocal caSession;
  /** EJB. */
  @EJB private CertificateCreateSessionLocal certificateCreateSession;
  /** EJB. */
  @EJB private CertificateProfileSessionLocal certificateProfileSession;
  /** EJB. */
  @EJB private CertificateStoreSessionLocal certificateStoreSession;
  /** EJB. */
  @EJB private CertReqHistorySessionLocal certReqHistorySession;
  /** EJB. */
  @EJB private CmpMessageDispatcherSessionLocal cmpMessageDispatcherSession;
  /** EJB. */
  @EJB private CrlCreateSessionLocal crlCreateSession;
  /** EJB. */
  @EJB private CrlStoreSessionLocal crlStoreSession;
  /** EJB. */
  @EJB private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
  /** EJB. */
  @EJB private CryptoTokenSessionLocal cryptoTokenSession;
  /** EJB. */
  @EJB private EjbcaAuditorSessionLocal ejbcaAuditorSession;
  /** EJB. */
  @EJB private EjbcaRestHelperSessionLocal ejbcaRestHelperSession;
  /** EJB. */
  @EJB private EjbcaWSHelperSessionLocal ejbcaWSHelperSession;
  /** EJB. */
  @EJB private EndEntityAccessSessionLocal endEntityAccessSession;
  /** EJB. */
  @EJB private EndEntityAuthenticationSessionLocal
      endEntityAuthenticationSession;
  /** EJB. */
  @EJB private EndEntityManagementSessionLocal endEntityManagementSession;
  /** EJB. */
  @EJB private EndEntityProfileSessionLocal endEntityProfileSession;
  /** EJB. */
  @EJB private GlobalConfigurationSessionLocal globalConfigurationSession;
  /** EJB. */
  @EJB private HardTokenBatchJobSessionLocal hardTokenBatchJobSession;
  /** EJB. */
  @EJB private HardTokenSessionLocal hardTokenSession;
  /** EJB. */
  @EJB private ImportCrlSessionLocal importCrlSession;
  /** EJB. */
  @EJB private InternalKeyBindingDataSessionLocal internalKeyBindingDataSession;
  /** EJB. */
  @EJB private InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession;
  /** EJB. */
  @EJB private KeyRecoverySessionLocal keyRecoverySession;
  /** EJB. */
  @EJB private KeyValidatorSessionLocal keyValidatorSession;
  /** EJB. */
  @EJB private PublisherQueueSessionLocal publisherQueueSession;
  /** EJB. */
  @EJB private PublisherSessionLocal publisherSession;
  /** EJB. */
  @EJB private PublishingCrlSessionLocal publishingCrlSession;
  /** EJB. */
  @EJB private RaMasterApiProxyBeanLocal raMasterApiProxyBean;
  /** EJB. */
  @EJB private RaMasterApiSessionLocal raMasterApiSession;
  /** EJB. */
  @EJB private RevocationSessionLocal revocationSession;
  /** EJB. */
  @EJB private RoleDataSessionLocal roleDataSession;
  /** EJB. */
  @EJB private RoleMemberDataSessionLocal roleMemberDataSession;
  /** EJB. */
  @EJB private RoleMemberSessionLocal roleMemberSession;
  /** EJB. */
  @EJB private RoleSessionLocal roleSession;
  /** EJB. */
  @EJB private SecurityEventsAuditorSessionLocal securityEventsAuditorSession;
  /** EJB. */
  @EJB private SecurityEventsLoggerSessionLocal securityEventsLoggerSession;
  /** EJB. */
  @EJB private ServiceSessionLocal serviceSession;
  /** EJB. */
  @EJB private SignSessionLocal signSession;
  /** EJB. */
  @EJB private UpgradeSessionLocal upgradeSession;
  /** EJB. */
  @EJB private UserDataSourceSessionLocal userDataSourceSession;
  /** EJB. */
  @EJB private WebAuthenticationProviderSessionLocal
      webAuthenticationProviderSession;

  @Override
  public AdminPreferenceSessionLocal getAdminPreferenceSession() {
    return adminPreferenceSession;
  }

  @Override
  public ApprovalExecutionSessionLocal getApprovalExecutionSession() {
    return approvalExecutionSession;
  }

  @Override
  public ApprovalProfileSessionLocal getApprovalProfileSession() {
    return approvalProfileSession;
  }

  @Override
  public ApprovalSessionLocal getApprovalSession() {
    return approvalSession;
  }

  @Override
  public AuthorizationSessionLocal getAuthorizationSession() {
    return authorizationSession;
  }

  @Override
  public AuthorizationSystemSessionLocal getAuthorizationSystemSession() {
    return authorizationSystemSession;
  }

  @Override
  public BlacklistSessionLocal getBlacklistSession() {
    return blacklistSession;
  }

  @Override
  public CAAdminSessionLocal getCaAdminSession() {
    return caAdminSession;
  }

  @Override
  public CaSessionLocal getCaSession() {
    return caSession;
  }

  @Override
  public CertificateCreateSessionLocal getCertificateCreateSession() {
    return certificateCreateSession;
  }

  @Override
  public CertificateProfileSessionLocal getCertificateProfileSession() {
    return certificateProfileSession;
  }

  @Override
  public CertificateStoreSessionLocal getCertificateStoreSession() {
    return certificateStoreSession;
  }

  @Override
  public CertReqHistorySessionLocal getCertReqHistorySession() {
    return certReqHistorySession;
  }

  @Override
  public CmpMessageDispatcherSessionLocal getCmpMessageDispatcherSession() {
    return cmpMessageDispatcherSession;
  }

  @Override
  public CrlCreateSessionLocal getCrlCreateSession() {
    return crlCreateSession;
  }

  @Override
  public CrlStoreSessionLocal getCrlStoreSession() {
    return crlStoreSession;
  }

  @Override
  public CryptoTokenManagementSessionLocal getCryptoTokenManagementSession() {
    return cryptoTokenManagementSession;
  }

  @Override
  public CryptoTokenSessionLocal getCryptoTokenSession() {
    return cryptoTokenSession;
  }

  @Override
  public EjbcaAuditorSessionLocal getEjbcaAuditorSession() {
    return ejbcaAuditorSession;
  }

  @Override
  public EjbcaRestHelperSessionLocal getEjbcaRestHelperSession() {
    return ejbcaRestHelperSession;
  }

  @Override
  public EjbcaWSHelperSessionLocal getEjbcaWSHelperSession() {
    return ejbcaWSHelperSession;
  }

  @Override
  public EndEntityAccessSessionLocal getEndEntityAccessSession() {
    return endEntityAccessSession;
  }

  @Override
  public EndEntityAuthenticationSessionLocal
      getEndEntityAuthenticationSession() {
    return endEntityAuthenticationSession;
  }

  @Override
  public EndEntityManagementSessionLocal getEndEntityManagementSession() {
    return endEntityManagementSession;
  }

  @Override
  public EndEntityProfileSessionLocal getEndEntityProfileSession() {
    return endEntityProfileSession;
  }

  @Override
  public GlobalConfigurationSessionLocal getGlobalConfigurationSession() {
    return globalConfigurationSession;
  }

  @Override
  public HardTokenBatchJobSessionLocal getHardTokenBatchJobSession() {
    return hardTokenBatchJobSession;
  }

  @Override
  public HardTokenSessionLocal getHardTokenSession() {
    return hardTokenSession;
  }

  @Override
  public ImportCrlSessionLocal getImportCrlSession() {
    return importCrlSession;
  }

  @Override
  public InternalKeyBindingDataSessionLocal getInternalKeyBindingDataSession() {
    return internalKeyBindingDataSession;
  }

  @Override
  public InternalKeyBindingMgmtSessionLocal getInternalKeyBindingMgmtSession() {
    return internalKeyBindingMgmtSession;
  }

  @Override
  public KeyRecoverySessionLocal getKeyRecoverySession() {
    return keyRecoverySession;
  }

  @Override
  public KeyValidatorSessionLocal getKeyValidatorSession() {
    return keyValidatorSession;
  }

  @Override
  public PublisherQueueSessionLocal getPublisherQueueSession() {
    return publisherQueueSession;
  }

  @Override
  public PublisherSessionLocal getPublisherSession() {
    return publisherSession;
  }

  @Override
  public PublishingCrlSessionLocal getPublishingCrlSession() {
    return publishingCrlSession;
  }

  @Override
  public RaMasterApiProxyBeanLocal getRaMasterApiProxyBean() {
    return raMasterApiProxyBean;
  }

  @Override
  public RaMasterApiSessionLocal getRaMasterApiSession() {
    return raMasterApiSession;
  }

  @Override
  public RevocationSessionLocal getRevocationSession() {
    return revocationSession;
  }

  @Override
  public RoleDataSessionLocal getRoleDataSession() {
    return roleDataSession;
  }

  @Override
  public RoleMemberDataSessionLocal getRoleMemberDataSession() {
    return roleMemberDataSession;
  }

  @Override
  public RoleMemberSessionLocal getRoleMemberSession() {
    return roleMemberSession;
  }

  @Override
  public RoleSessionLocal getRoleSession() {
    return roleSession;
  }

  @Override
  public SecurityEventsAuditorSessionLocal getSecurityEventsAuditorSession() {
    return securityEventsAuditorSession;
  }

  @Override
  public SecurityEventsLoggerSessionLocal getSecurityEventsLoggerSession() {
    return securityEventsLoggerSession;
  }

  @Override
  public ServiceSessionLocal getServiceSession() {
    return serviceSession;
  }

  @Override
  public SignSessionLocal getSignSession() {
    return signSession;
  }

  @Override
  public UpgradeSessionLocal getUpgradeSession() {
    return upgradeSession;
  }

  @Override
  public UserDataSourceSessionLocal getUserDataSourceSession() {
    return userDataSourceSession;
  }

  @Override
  public WebAuthenticationProviderSessionLocal
      getWebAuthenticationProviderSession() {
    return webAuthenticationProviderSession;
  }
}
