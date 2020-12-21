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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.CertTools;
import org.cesecore.util.ProfileID;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceResponse;
import org.ejbca.core.model.hardtoken.HardTokenDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenExistsException;
import org.ejbca.core.model.hardtoken.HardTokenInformation;
import org.ejbca.core.model.hardtoken.HardTokenIssuer;
import org.ejbca.core.model.hardtoken.HardTokenIssuerInformation;
import org.ejbca.core.model.hardtoken.HardTokenProfileExistsException;
import org.ejbca.core.model.hardtoken.UnavailableTokenException;
import org.ejbca.core.model.hardtoken.profiles.EIDProfile;
import org.ejbca.core.model.hardtoken.profiles.EnhancedEIDProfile;
import org.ejbca.core.model.hardtoken.profiles.HardTokenProfile;
import org.ejbca.core.model.hardtoken.profiles.SwedishEIDProfile;
import org.ejbca.core.model.hardtoken.profiles.TurkishEIDProfile;
import org.ejbca.core.model.hardtoken.types.EIDHardToken;
import org.ejbca.core.model.hardtoken.types.EnhancedEIDHardToken;
import org.ejbca.core.model.hardtoken.types.HardToken;
import org.ejbca.core.model.hardtoken.types.SwedishEIDHardToken;
import org.ejbca.core.model.hardtoken.types.TurkishEIDHardToken;

/**
 * HardToken API, this mimics "smart card" tokens where one token that has a
 * serial number may care multiple certificates. Different types of hard tokens
 * have different profiles.
 *
 * @version $Id: HardTokenSessionBean.java 29010 2018-05-23 13:09:53Z
 *     jekaterina_b_helmes $
 */
@Stateless(
    mappedName = JndiConstants.APP_JNDI_PREFIX + "HardTokenSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class HardTokenSessionBean
    implements HardTokenSessionLocal, HardTokenSessionRemote {

    /** Lohher. */
  private static final Logger LOG =
      Logger.getLogger(EjbcaHardTokenBatchJobSessionBean.class);
  /** Internal localization of logs and errors. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();

  /** EM. */
  @PersistenceContext(unitName = "ejbca")
  private EntityManager entityManager;

  /** EJB. */
  @EJB private AuthorizationSessionLocal authorizationSession;
  /** EJB. */
  @EJB private CAAdminSessionLocal caAdminSession;
  /** EJB. */
  @EJB private CaSessionLocal caSession;
  /** EJB. */
  @EJB private GlobalConfigurationSessionLocal globalConfigurationSession;
  /** EJB. */
  @EJB private CertificateProfileSessionLocal certificateProfileSession;
  /** EJB. */
  @EJB private CertificateStoreSessionLocal certificateStoreSession;
  /** EJB. */
  @EJB private RoleSessionLocal roleSession;
  /** EJB. */
  @EJB private SecurityEventsLoggerSessionLocal auditSession;
  /** Const. */
  public static final int NO_ISSUER = 0;

  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public void addHardTokenProfile(
      final AuthenticationToken admin,
      final String name,
      final HardTokenProfile profile)
      throws HardTokenProfileExistsException, AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">addHardTokenProfile(name: " + name + ")");
    }
    addHardTokenProfile(admin, findFreeHardTokenProfileId(), name, profile);
    if (LOG.isTraceEnabled()) {
      LOG.trace("<addHardTokenProfile()");
    }
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public void addHardTokenProfile(
      final AuthenticationToken admin,
      final int profileid,
      final String name,
      final HardTokenProfile profile)
      throws HardTokenProfileExistsException, AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">addHardTokenProfile(name: " + name + ", id: " + profileid + ")");
    }
    addHardTokenProfileInternal(admin, profileid, name, profile);
    final String msg =
        INTRES.getLocalizedMessage("hardtoken.addedprofile", name);
    final Map<String, Object> details = new LinkedHashMap<String, Object>();
    details.put("msg", msg);
    auditSession.log(
        EjbcaEventTypes.HARDTOKEN_ADDPROFILE,
        EventStatus.SUCCESS,
        EjbcaModuleTypes.HARDTOKEN,
        EjbcaServiceTypes.EJBCA,
        admin.toString(),
        null,
        null,
        null,
        details);
    if (LOG.isTraceEnabled()) {
      LOG.trace("<addHardTokenProfile()");
    }
  }

  private void addHardTokenProfileInternal(
      final AuthenticationToken admin,
      final int profileid,
      final String name,
      final HardTokenProfile profile)
      throws HardTokenProfileExistsException, AuthorizationDeniedException {
    authorizedToEditProfile(admin);
    if (HardTokenProfileData.findByName(entityManager, name) == null
        && HardTokenProfileData.findByPK(entityManager, profileid) == null) {
      entityManager.persist(new HardTokenProfileData(profileid, name, profile));
    } else {
      final String msg =
          INTRES.getLocalizedMessage("hardtoken.erroraddprofile", name);
      LOG.info(msg);
      throw new HardTokenProfileExistsException();
    }
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public void changeHardTokenProfile(
      final AuthenticationToken admin,
      final String name,
      final HardTokenProfile profile)
      throws AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">changeHardTokenProfile(name: " + name + ")");
    }
    authorizedToEditProfile(admin);
    HardTokenProfileData htp =
        HardTokenProfileData.findByName(entityManager, name);
    if (htp != null) {
      // Make a diff what has changed
      final HardTokenProfile oldhtp = getHardTokenProfile(htp);
      final Map<Object, Object> diff = oldhtp.diff(profile);
      htp.setHardTokenProfile(profile);
      final String msg =
          INTRES.getLocalizedMessage("hardtoken.editedprofile", name);
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      for (Map.Entry<Object, Object> entry : diff.entrySet()) {
        details.put(entry.getKey().toString(), entry.getValue().toString());
      }
      auditSession.log(
          EjbcaEventTypes.HARDTOKEN_EDITPROFILE,
          EventStatus.SUCCESS,
          EjbcaModuleTypes.HARDTOKEN,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          null,
          null,
          details);
    } else {
      final String msg =
          INTRES.getLocalizedMessage("hardtoken.erroreditprofile", name);
      LOG.info(msg);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<changeHardTokenProfile()");
    }
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public void cloneHardTokenProfile(
      final AuthenticationToken admin,
      final String oldname,
      final String newname)
      throws HardTokenProfileExistsException, AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">cloneHardTokenProfile(name: " + oldname + ")");
    }
    HardTokenProfileData htp =
        HardTokenProfileData.findByName(entityManager, oldname);
    try {
      HardTokenProfile profiledata =
          (HardTokenProfile) getHardTokenProfile(htp).clone();
      try {
        addHardTokenProfileInternal(
            admin, findFreeHardTokenProfileId(), newname, profiledata);
        final String msg =
            INTRES.getLocalizedMessage(
                "hardtoken.clonedprofile", newname, oldname);
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        auditSession.log(
            EjbcaEventTypes.HARDTOKEN_ADDPROFILE,
            EventStatus.SUCCESS,
            EjbcaModuleTypes.HARDTOKEN,
            EjbcaServiceTypes.EJBCA,
            admin.toString(),
            null,
            null,
            null,
            details);
      } catch (HardTokenProfileExistsException f) {
        final String msg =
            INTRES.getLocalizedMessage(
                "hardtoken.errorcloneprofile", newname, oldname);
        LOG.info(msg);
        throw f;
      }
    } catch (CloneNotSupportedException e) {
      throw new EJBException(e);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<cloneHardTokenProfile()");
    }
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public void removeHardTokenProfile(
      final AuthenticationToken admin, final String name)
      throws AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">removeHardTokenProfile(name: " + name + ")");
    }
    authorizedToEditProfile(admin);
    try {
      HardTokenProfileData htp =
          HardTokenProfileData.findByName(entityManager, name);
      if (htp == null) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Trying to remove HardTokenProfileData that does not exist: "
                  + name);
        }
      } else {
        entityManager.remove(htp);
        final String msg =
            INTRES.getLocalizedMessage("hardtoken.removedprofile", name);
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        auditSession.log(
            EjbcaEventTypes.HARDTOKEN_REMOVEPROFILE,
            EventStatus.SUCCESS,
            EjbcaModuleTypes.HARDTOKEN,
            EjbcaServiceTypes.EJBCA,
            admin.toString(),
            null,
            null,
            null,
            details);
      }
    } catch (Exception e) {
      final String msg =
          INTRES.getLocalizedMessage("hardtoken.errorremoveprofile", name);
      LOG.info(msg);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<removeHardTokenProfile()");
    }
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public void renameHardTokenProfile(
      final AuthenticationToken admin,
      final String oldname,
      final String newname)
      throws HardTokenProfileExistsException, AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">renameHardTokenProfile(from " + oldname + " to " + newname + ")");
    }
    boolean success = false;
    authorizedToEditProfile(admin);
    if (HardTokenProfileData.findByName(entityManager, newname) == null) {
      HardTokenProfileData htp =
          HardTokenProfileData.findByName(entityManager, oldname);
      if (htp != null) {
        htp.setName(newname);
        success = true;
      }
    }
    if (success) {
      final String msg =
          INTRES.getLocalizedMessage(
              "hardtoken.renamedprofile", oldname, newname);
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.HARDTOKEN_EDITPROFILE,
          EventStatus.SUCCESS,
          EjbcaModuleTypes.HARDTOKEN,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          null,
          null,
          details);
    } else {
      final String msg =
          INTRES.getLocalizedMessage(
              "hardtoken.errorrenameprofile", oldname, newname);
      LOG.info(msg);
      throw new HardTokenProfileExistsException();
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<renameHardTokenProfile()");
    }
  }

  @Override
  public Collection<Integer> getAuthorizedHardTokenProfileIds(
      final AuthenticationToken admin) {
    ArrayList<Integer> returnval = new ArrayList<Integer>();
    HashSet<Integer> authorizedcertprofiles =
        new HashSet<Integer>(
            certificateProfileSession.getAuthorizedCertificateProfileIds(
                admin, CertificateConstants.CERTTYPE_HARDTOKEN));
    // It should be possible to indicate that a certificate should not be
    // generated by not specifying a cert profile for this key.
    authorizedcertprofiles.add(
        Integer.valueOf(CertificateProfileConstants.CERTPROFILE_NO_PROFILE));
    HashSet<Integer> authorizedcaids =
        new HashSet<Integer>(caSession.getAuthorizedCaIds(admin));
    Collection<HardTokenProfileData> result =
        HardTokenProfileData.findAll(entityManager);
    Iterator<HardTokenProfileData> i = result.iterator();
    while (i.hasNext()) {
      HardTokenProfileData next = i.next();
      HardTokenProfile profile = getHardTokenProfile(next);
      if (profile instanceof EIDProfile) {
        if (authorizedcertprofiles.containsAll(
                ((EIDProfile) profile).getAllCertificateProfileIds())
            && authorizedcaids.containsAll(
                ((EIDProfile) profile).getAllCAIds())) {
          returnval.add(next.getId());
        }
      } else {
        // Implement for other profile types
      }
    }
    return returnval;
  }

  private void authorizedToEditProfile(final AuthenticationToken admin)
      throws AuthorizationDeniedException {
    // We need to check that admin also have rights to edit certificate profiles
    if (!authorizationSession.isAuthorized(
        admin, AccessRulesConstants.HARDTOKEN_EDITHARDTOKENPROFILES)) {
      final String msg =
          INTRES.getLocalizedMessage(
              "authorization.notauthorizedtoresource",
              AccessRulesConstants.HARDTOKEN_EDITHARDTOKENPROFILES,
              null);
      throw new AuthorizationDeniedException(msg);
    }
  }

  @Override
  public HashMap<Integer, String> getHardTokenProfileIdToNameMap() {
    HashMap<Integer, String> returnval = new HashMap<Integer, String>();
    Collection<HardTokenProfileData> result =
        HardTokenProfileData.findAll(entityManager);
    Iterator<HardTokenProfileData> i = result.iterator();
    while (i.hasNext()) {
      HardTokenProfileData next = i.next();
      returnval.put(next.getId(), next.getName());
    }
    return returnval;
  }

  @Override
  public HardTokenProfile getHardTokenProfile(final String name) {
    HardTokenProfile returnval = null;
    HardTokenProfileData htpd =
        HardTokenProfileData.findByName(entityManager, name);
    if (htpd != null) {
      returnval = getHardTokenProfile(htpd);
    }
    return returnval;
  }

  @Override
  public HardTokenProfile getHardTokenProfile(final int id) {
    HardTokenProfile returnval = null;
    HardTokenProfileData htpd =
        HardTokenProfileData.findByPK(entityManager, Integer.valueOf(id));
    if (htpd != null) {
      returnval = getHardTokenProfile(htpd);
    }
    return returnval;
  }

  @Override
  public int getHardTokenProfileUpdateCount(final int hardtokenprofileid) {
    int returnval = 0;
    HardTokenProfileData htpd =
        HardTokenProfileData.findByPK(
            entityManager, Integer.valueOf(hardtokenprofileid));
    if (htpd != null) {
      returnval = htpd.getUpdateCounter();
    }
    return returnval;
  }

  @Override
  public int getHardTokenProfileId(final String name) {
    int returnval = 0;
    HardTokenProfileData htpd =
        HardTokenProfileData.findByName(entityManager, name);
    if (htpd != null) {
      returnval = htpd.getId();
    }
    return returnval;
  }

  @Override
  public String getHardTokenProfileName(final int id) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getHardTokenProfileName(id: " + id + ")");
    }
    String returnval = null;
    HardTokenProfileData htpd =
        HardTokenProfileData.findByPK(entityManager, Integer.valueOf(id));
    if (htpd != null) {
      returnval = htpd.getName();
    }
    LOG.trace("<getHardTokenProfileName()");
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public boolean addHardTokenIssuer(
      final AuthenticationToken admin,
      final String alias,
      final int admingroupid,
      final HardTokenIssuer issuerdata)
      throws AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">addHardTokenIssuer(alias: " + alias + ")");
    }
    boolean returnval =
        addhardTokenIssuerInternal(admin, alias, admingroupid, issuerdata);
    if (returnval) {
      String msg = INTRES.getLocalizedMessage("hardtoken.addedissuer", alias);
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.HARDTOKEN_ADDISSUER,
          EventStatus.SUCCESS,
          EjbcaModuleTypes.HARDTOKEN,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          null,
          null,
          details);
    } else {
      // Does not exist
      String msg =
          INTRES.getLocalizedMessage("hardtoken.erroraddissuer", alias);
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.HARDTOKEN_ADDISSUER,
          EventStatus.FAILURE,
          EjbcaModuleTypes.HARDTOKEN,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          null,
          null,
          details);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<addHardTokenIssuer()");
    }
    return returnval;
  }

  private boolean addhardTokenIssuerInternal(
      final AuthenticationToken admin,
      final String alias,
      final int admingroupid,
      final HardTokenIssuer issuerdata)
      throws AuthorizationDeniedException {
    boolean returnval = false;
    authorizedToEditIssuer(admin);
    if (HardTokenIssuerData.findByAlias(entityManager, alias) == null) {
      entityManager.persist(
          new HardTokenIssuerData(
              findFreeHardTokenIssuerId(), alias, admingroupid, issuerdata));
      returnval = true;
    }
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public boolean changeHardTokenIssuer(
      final AuthenticationToken admin,
      final String alias,
      final HardTokenIssuer issuerdata)
      throws AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">changeHardTokenIssuer(alias: " + alias + ")");
    }
    boolean returnvalue = false;
    authorizedToEditIssuer(admin);
    HardTokenIssuerData htih =
        HardTokenIssuerData.findByAlias(entityManager, alias);
    if (htih != null) {
      final HardTokenIssuer oldissuer = htih.getHardTokenIssuer();
      final Map<Object, Object> diff = oldissuer.diff(issuerdata);
      htih.setHardTokenIssuer(issuerdata);
      String msg = INTRES.getLocalizedMessage("hardtoken.editedissuer", alias);
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      for (Map.Entry<Object, Object> entry : diff.entrySet()) {
        details.put(entry.getKey().toString(), entry.getValue().toString());
      }
      auditSession.log(
          EjbcaEventTypes.HARDTOKEN_EDITISSUER,
          EventStatus.SUCCESS,
          EjbcaModuleTypes.HARDTOKEN,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          null,
          null,
          details);
      returnvalue = true;
    } else {
      // Does not exist
      String msg =
          INTRES.getLocalizedMessage("hardtoken.erroreditissuer", alias);
      LOG.info(msg);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<changeHardTokenIssuer()");
    }
    return returnvalue;
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public boolean cloneHardTokenIssuer(
      final AuthenticationToken admin,
      final String oldalias,
      final String newalias,
      final int admingroupid)
      throws AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">cloneHardTokenIssuer(alias: " + oldalias + ")");
    }
    boolean returnval = false;
    HardTokenIssuerData htih =
        HardTokenIssuerData.findByAlias(entityManager, oldalias);
    if (htih != null) {
      try {
        HardTokenIssuer issuerdata =
            (HardTokenIssuer) htih.getHardTokenIssuer().clone();
        returnval =
            addhardTokenIssuerInternal(
                admin, newalias, admingroupid, issuerdata);
      } catch (CloneNotSupportedException e) {
      }
    }
    if (returnval) {
      String msg =
          INTRES.getLocalizedMessage(
              "hardtoken.clonedissuer", newalias, oldalias);
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.HARDTOKEN_ADDISSUER,
          EventStatus.SUCCESS,
          EjbcaModuleTypes.HARDTOKEN,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          null,
          null,
          details);
    } else {
      // Does not exist
      String msg =
          INTRES.getLocalizedMessage(
              "hardtoken.errorcloneissuer", newalias, oldalias);
      LOG.info(msg);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<cloneHardTokenIssuer()");
    }
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public void removeHardTokenIssuer(
      final AuthenticationToken admin, final String alias)
      throws AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">removeHardTokenIssuer(alias: " + alias + ")");
    }
    authorizedToEditIssuer(admin);
    try {
      HardTokenIssuerData htih =
          HardTokenIssuerData.findByAlias(entityManager, alias);
      if (htih == null) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Trying to remove HardTokenProfileData that does not exist: "
                  + alias);
        }
      } else {
        entityManager.remove(htih);
        String msg =
            INTRES.getLocalizedMessage("hardtoken.removedissuer", alias);
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        auditSession.log(
            EjbcaEventTypes.HARDTOKEN_REMOVEISSUER,
            EventStatus.SUCCESS,
            EjbcaModuleTypes.HARDTOKEN,
            EjbcaServiceTypes.EJBCA,
            admin.toString(),
            null,
            null,
            null,
            details);
      }
    } catch (Exception e) {
      String msg =
          INTRES.getLocalizedMessage("hardtoken.errorremoveissuer", alias);
      LOG.info(msg, e);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<removeHardTokenIssuer()");
    }
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public boolean renameHardTokenIssuer(
      final AuthenticationToken admin,
      final String oldalias,
      final String newalias,
      final int newadmingroupid)
      throws AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">renameHardTokenIssuer(from " + oldalias + " to " + newalias + ")");
    }
    authorizedToEditIssuer(admin);
    boolean returnvalue = false;
    if (HardTokenIssuerData.findByAlias(entityManager, newalias) == null) {
      HardTokenIssuerData htih =
          HardTokenIssuerData.findByAlias(entityManager, oldalias);
      if (htih != null) {
        htih.setAlias(newalias);
        htih.setAdminGroupId(newadmingroupid);
        returnvalue = true;
      }
    }
    if (returnvalue) {
      String msg =
          INTRES.getLocalizedMessage(
              "hardtoken.renameissuer", oldalias, newalias);
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.HARDTOKEN_EDITISSUER,
          EventStatus.SUCCESS,
          EjbcaModuleTypes.HARDTOKEN,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          null,
          null,
          details);
    } else {
      // Does not exist
      String msg =
          INTRES.getLocalizedMessage(
              "hardtoken.errorrenameissuer", oldalias, newalias);
      LOG.info(msg);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<renameHardTokenIssuer()");
    }
    return returnvalue;
  }

  @Override
  public boolean isAuthorizedToEditHardTokenIssuer(
      final AuthenticationToken token, final String alias) {
    TreeMap<String, HardTokenIssuerInformation> authorizedIssuers =
        getHardTokenIssuers(token);
    return authorizationSession.isAuthorizedNoLogging(
            token, AccessRulesConstants.HARDTOKEN_EDITHARDTOKENISSUERS)
        && authorizedIssuers.containsKey(alias);
  }

  @Override
  public boolean isAuthorizedToHardTokenIssuer(
      final AuthenticationToken admin, final String alias) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">isAuthorizedToHardTokenIssuer(" + alias + ")");
    }
    boolean returnval = false;
    HardTokenIssuerData htih =
        HardTokenIssuerData.findByAlias(entityManager, alias);
    if (htih != null) {
      if (authorizationSession.isAuthorizedNoLogging(
          admin, AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS)) {
        final List<Role> roles =
            roleSession.getRolesAuthenticationTokenIsMemberOf(admin);
        for (final Role role : roles) {
          if (role.getRoleId() == htih.getAdminGroupId()) {
            returnval = true;
            break;
          }
        }
      }
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<isAuthorizedToHardTokenIssuer(" + returnval + ")");
    }
    return returnval;
  }

  private void authorizedToEditIssuer(final AuthenticationToken admin)
      throws AuthorizationDeniedException {
    // We need to check that admin also have rights to edit certificate profiles
    if (!authorizationSession.isAuthorized(
        admin, AccessRulesConstants.HARDTOKEN_EDITHARDTOKENISSUERS)) {
      final String msg =
          INTRES.getLocalizedMessage(
              "authorization.notauthorizedtoresource",
              AccessRulesConstants.HARDTOKEN_EDITHARDTOKENISSUERS,
              null);
      throw new AuthorizationDeniedException(msg);
    }
  }

  @Override
  public Collection<HardTokenIssuerInformation> getHardTokenIssuerDatas(
      final AuthenticationToken admin) {
    LOG.trace(">getHardTokenIssuerDatas()");
    ArrayList<HardTokenIssuerInformation> returnval =
        new ArrayList<HardTokenIssuerInformation>();
    Collection<Integer> authorizedhardtokenprofiles =
        getAuthorizedHardTokenProfileIds(admin);
    Collection<HardTokenIssuerData> result =
        HardTokenIssuerData.findAll(entityManager);
    Iterator<HardTokenIssuerData> i = result.iterator();
    while (i.hasNext()) {
      HardTokenIssuerData htih = i.next();
      if (authorizedhardtokenprofiles.containsAll(
          htih.getHardTokenIssuer().getAvailableHardTokenProfiles())) {
        returnval.add(
            new HardTokenIssuerInformation(
                htih.getId(),
                htih.getAlias(),
                htih.getAdminGroupId(),
                htih.getHardTokenIssuer()));
      }
    }
    Collections.sort(returnval);
    LOG.trace("<getHardTokenIssuerDatas()");
    return returnval;
  }

  @Override
  public Collection<String> getHardTokenIssuerAliases(
      final AuthenticationToken admin) {
    LOG.trace(">getHardTokenIssuerAliases()");
    ArrayList<String> returnval = new ArrayList<String>();
    Collection<Integer> authorizedhardtokenprofiles =
        getAuthorizedHardTokenProfileIds(admin);
    Collection<HardTokenIssuerData> result =
        HardTokenIssuerData.findAll(entityManager);
    Iterator<HardTokenIssuerData> i = result.iterator();
    while (i.hasNext()) {
      HardTokenIssuerData htih = i.next();
      if (authorizedhardtokenprofiles.containsAll(
          htih.getHardTokenIssuer().getAvailableHardTokenProfiles())) {
        returnval.add(htih.getAlias());
      }
    }
    Collections.sort(returnval);
    LOG.trace("<getHardTokenIssuerAliases()");
    return returnval;
  }

  @Override
  public TreeMap<String, HardTokenIssuerInformation> getHardTokenIssuers(
      final AuthenticationToken admin) {
    LOG.trace(">getHardTokenIssuers()");
    Collection<Integer> authorizedhardtokenprofiles =
        getAuthorizedHardTokenProfileIds(admin);
    TreeMap<String, HardTokenIssuerInformation> returnval =
        new TreeMap<String, HardTokenIssuerInformation>();
    Collection<HardTokenIssuerData> result =
        HardTokenIssuerData.findAll(entityManager);
    Iterator<HardTokenIssuerData> i = result.iterator();
    while (i.hasNext()) {
      HardTokenIssuerData htih = i.next();
      if (authorizedhardtokenprofiles.containsAll(
          htih.getHardTokenIssuer().getAvailableHardTokenProfiles())) {
        returnval.put(
            htih.getAlias(),
            new HardTokenIssuerInformation(
                htih.getId(),
                htih.getAlias(),
                htih.getAdminGroupId(),
                htih.getHardTokenIssuer()));
      }
    }
    LOG.trace("<getHardTokenIssuers()");
    return returnval;
  }

  @Override
  public HardTokenIssuerInformation getHardTokenIssuerInformation(
      final String alias) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getHardTokenIssuerData(alias: " + alias + ")");
    }
    HardTokenIssuerInformation returnval = null;
    HardTokenIssuerData htih =
        HardTokenIssuerData.findByAlias(entityManager, alias);
    if (htih != null) {
      returnval =
          new HardTokenIssuerInformation(
              htih.getId(),
              htih.getAlias(),
              htih.getAdminGroupId(),
              htih.getHardTokenIssuer());
    }
    LOG.trace("<getHardTokenIssuerData()");
    return returnval;
  }

  @Override
  public HardTokenIssuerInformation getHardTokenIssuerInformation(
      final int id) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getHardTokenIssuerData(id: " + id + ")");
    }
    HardTokenIssuerInformation returnval = null;
    HardTokenIssuerData htih =
        HardTokenIssuerData.findByPK(entityManager, Integer.valueOf(id));
    if (htih != null) {
      returnval =
          new HardTokenIssuerInformation(
              htih.getId(),
              htih.getAlias(),
              htih.getAdminGroupId(),
              htih.getHardTokenIssuer());
    }
    LOG.trace("<getHardTokenIssuerData()");
    return returnval;
  }

  @Override
  public int getNumberOfHardTokenIssuers(final AuthenticationToken admin) {
    LOG.trace(">getNumberOfHardTokenIssuers()");
    int returnval = HardTokenIssuerData.findAll(entityManager).size();
    LOG.trace("<getNumberOfHardTokenIssuers()");
    return returnval;
  }

  @Override
  public int getHardTokenIssuerId(final String alias) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getHardTokenIssuerId(alias: " + alias + ")");
    }
    int returnval = NO_ISSUER;
    HardTokenIssuerData htih =
        HardTokenIssuerData.findByAlias(entityManager, alias);
    if (htih != null) {
      returnval = htih.getId();
    }
    LOG.trace("<getHardTokenIssuerId()");
    return returnval;
  }

  @Override
  public String getHardTokenIssuerAlias(final int id) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getHardTokenIssuerAlias(id: " + id + ")");
    }
    String returnval = null;
    if (id != 0) {
      HardTokenIssuerData htih =
          HardTokenIssuerData.findByPK(entityManager, Integer.valueOf(id));
      if (htih != null) {
        returnval = htih.getAlias();
      }
    }
    LOG.trace("<getHardTokenIssuerAlias()");
    return returnval;
  }

  /*
   * TODO: Somebody please clean the hell out of this method =) -mikek
   *
   * getIs? srsly? and then toss an exception? orly?
   */
  @Override
  public void getIsHardTokenProfileAvailableToIssuer(
      final int issuerid, final EndEntityInformation userdata)
      throws UnavailableTokenException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">getIsTokenTypeAvailableToIssuer(issuerid: "
              + issuerid
              + ", tokentype: "
              + userdata.getTokenType()
              + ")");
    }
    boolean returnval = false;
    ArrayList<Integer> availabletokentypes =
        getHardTokenIssuerInformation(issuerid)
            .getHardTokenIssuer()
            .getAvailableHardTokenProfiles();
    for (int i = 0; i < availabletokentypes.size(); i++) {
      if (availabletokentypes.get(i).intValue() == userdata.getTokenType()) {
        returnval = true;
      }
    }
    if (!returnval) {
      String msg =
          INTRES.getLocalizedMessage(
              "hardtoken.unavailabletoken", userdata.getUsername());
      throw new UnavailableTokenException(msg);
    }
    LOG.trace("<getIsTokenTypeAvailableToIssuer()");
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public void addHardToken(
      final AuthenticationToken admin,
      final String tokensn,
      final String username,
      final String significantissuerdn,
      final int tokentype,
      final HardToken hardtokendata,
      final Collection<Certificate> certificates,
      final String copyof)
      throws HardTokenExistsException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">addHardToken(tokensn : " + tokensn + ")");
    }
    final String bcdn = CertTools.stringToBCDNString(significantissuerdn);
    final HardTokenData data =
        HardTokenData.findByTokenSN(entityManager, tokensn);
    if (data != null) {
      String msg = INTRES.getLocalizedMessage("hardtoken.tokenexists", tokensn);
      LOG.info(msg);
      throw new HardTokenExistsException(
          "Hard token with serial number '" + tokensn + "' does exist.");
    }
    entityManager.persist(
        new HardTokenData(
            tokensn,
            username,
            new java.util.Date(),
            new java.util.Date(),
            tokentype,
            bcdn,
            setHardToken(
                admin,
                ((GlobalConfiguration)
                        globalConfigurationSession.getCachedConfiguration(
                            GlobalConfiguration.GLOBAL_CONFIGURATION_ID))
                    .getHardTokenEncryptCA(),
                hardtokendata)));
    if (certificates != null) {
      for (Certificate cert : certificates) {
        addHardTokenCertificateMapping(admin, tokensn, cert);
      }
    }
    if (copyof != null) {
      entityManager.persist(
          new HardTokenPropertyData(
              tokensn, HardTokenPropertyData.PROPERTY_COPYOF, copyof));
    }
    String msg = INTRES.getLocalizedMessage("hardtoken.addedtoken", tokensn);
    final Map<String, Object> details = new LinkedHashMap<String, Object>();
    details.put("msg", msg);
    auditSession.log(
        EjbcaEventTypes.HARDTOKEN_ADD,
        EventStatus.SUCCESS,
        EjbcaModuleTypes.HARDTOKEN,
        EjbcaServiceTypes.EJBCA,
        admin.toString(),
        null,
        null,
        username,
        details);
    LOG.trace("<addHardToken()");
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public void changeHardToken(
      final AuthenticationToken admin,
      final String tokensn,
      final int tokentype,
      final HardToken hardtokendata)
      throws HardTokenDoesntExistsException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">changeHardToken(tokensn : " + tokensn + ")");
    }
    final HardTokenData htd =
        HardTokenData.findByTokenSN(entityManager, tokensn);
    if (htd == null) {
      String msg =
          INTRES.getLocalizedMessage("hardtoken.errorchangetoken", tokensn);
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      final String errorMessage =
          "Hard token with serial number '" + tokensn + "' does not exist.";
      details.put("error", errorMessage);
      auditSession.log(
          EjbcaEventTypes.HARDTOKEN_EDIT,
          EventStatus.FAILURE,
          EjbcaModuleTypes.HARDTOKEN,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          null,
          null,
          details);
      throw new HardTokenDoesntExistsException(errorMessage);
    }
    htd.setTokenType(tokentype);
    htd.setData(
        setHardToken(
            admin,
            ((GlobalConfiguration)
                    globalConfigurationSession.getCachedConfiguration(
                        GlobalConfiguration.GLOBAL_CONFIGURATION_ID))
                .getHardTokenEncryptCA(),
            hardtokendata));
    htd.setModifyTime(new java.util.Date());
    int caid = htd.getSignificantIssuerDN().hashCode();
    String msg = INTRES.getLocalizedMessage("hardtoken.changedtoken", tokensn);
    final Map<String, Object> details = new LinkedHashMap<String, Object>();
    details.put("msg", msg);
    auditSession.log(
        EjbcaEventTypes.HARDTOKEN_EDIT,
        EventStatus.SUCCESS,
        EjbcaModuleTypes.HARDTOKEN,
        EjbcaServiceTypes.EJBCA,
        admin.toString(),
        String.valueOf(caid),
        null,
        htd.getUsername(),
        details);
    LOG.trace("<changeHardToken()");
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public void removeHardToken(
      final AuthenticationToken admin, final String tokensn)
      throws HardTokenDoesntExistsException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">removeHardToken(tokensn : " + tokensn + ")");
    }

    HardTokenData htd = HardTokenData.findByTokenSN(entityManager, tokensn);
    if (htd == null) {
      String msg =
          INTRES.getLocalizedMessage("hardtoken.errorremovetoken", tokensn);
      LOG.info(msg);
      throw new HardTokenDoesntExistsException("Tokensn : " + tokensn);
    }
    int caid = htd.getSignificantIssuerDN().hashCode();
    entityManager.remove(htd);
    // Remove all certificate mappings.
    removeHardTokenCertificateMappings(admin, tokensn);
    // Remove all copyof references id property database if they exist.
    HardTokenPropertyData htpd =
        HardTokenPropertyData.findByProperty(
            entityManager, tokensn, HardTokenPropertyData.PROPERTY_COPYOF);
    if (htpd != null) {
      entityManager.remove(htpd);
    }

    for (HardTokenPropertyData hardTokenPropertyData
        : HardTokenPropertyData.findIdsByPropertyAndValue(
            entityManager, HardTokenPropertyData.PROPERTY_COPYOF, tokensn)) {
      entityManager.remove(hardTokenPropertyData);
    }
    String msg = INTRES.getLocalizedMessage("hardtoken.removedtoken", tokensn);
    final Map<String, Object> details = new LinkedHashMap<String, Object>();
    details.put("msg", msg);
    auditSession.log(
        EjbcaEventTypes.HARDTOKEN_REMOVE,
        EventStatus.SUCCESS,
        EjbcaModuleTypes.HARDTOKEN,
        EjbcaServiceTypes.EJBCA,
        admin.toString(),
        String.valueOf(caid),
        null,
        htd.getUsername(),
        details);
    LOG.trace("<removeHardToken()");
  }

  @Override
  public boolean existsHardToken(final String tokensn) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">existsHardToken(tokensn : " + tokensn + ")");
    }
    boolean ret = false;
    if (HardTokenData.findByTokenSN(entityManager, tokensn) != null) {
      ret = true;
    }
    LOG.trace("<existsHardToken(): " + ret);
    return ret;
  }

  @Override
  public HardTokenInformation getHardToken(
      final AuthenticationToken admin,
      final String tokensn,
      final boolean includePUK)
      throws AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getHardToken(tokensn :" + tokensn + ")");
    }
    HardTokenInformation returnval = null;
    HardTokenData htd = HardTokenData.findByTokenSN(entityManager, tokensn);
    if (htd != null) {
      // Find Copyof
      String copyof = null;
      HardTokenPropertyData htpd =
          HardTokenPropertyData.findByProperty(
              entityManager, tokensn, HardTokenPropertyData.PROPERTY_COPYOF);
      if (htpd != null) {
        copyof = htpd.getValue();
      }
      ArrayList<String> copies = null;
      if (copyof == null) {
        // Find Copies
        Collection<HardTokenPropertyData> copieslocal =
            HardTokenPropertyData.findIdsByPropertyAndValue(
                entityManager, HardTokenPropertyData.PROPERTY_COPYOF, tokensn);
        if (copieslocal.size() > 0) {
          copies = new ArrayList<String>();
          Iterator<HardTokenPropertyData> iter = copieslocal.iterator();
          while (iter.hasNext()) {
            copies.add(iter.next().getId());
          }
        }
      }
      if (htd != null) {
        returnval =
            new HardTokenInformation(
                htd.getTokenSN(),
                htd.getUsername(),
                htd.getCreateTime(),
                htd.getModifyTime(),
                htd.getTokenType(),
                htd.getSignificantIssuerDN(),
                getHardToken(
                    admin,
                    ((GlobalConfiguration)
                            globalConfigurationSession.getCachedConfiguration(
                                GlobalConfiguration.GLOBAL_CONFIGURATION_ID))
                        .getHardTokenEncryptCA(),
                    includePUK,
                    htd.getData()),
                copyof,
                copies);
        int caid = htd.getSignificantIssuerDN().hashCode();
        String msg =
            INTRES.getLocalizedMessage("hardtoken.viewedtoken", tokensn);
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        auditSession.log(
            EjbcaEventTypes.HARDTOKEN_VIEWED,
            EventStatus.SUCCESS,
            EjbcaModuleTypes.HARDTOKEN,
            EjbcaServiceTypes.EJBCA,
            admin.toString(),
            String.valueOf(caid),
            null,
            htd.getUsername(),
            details);
        if (includePUK) {
          msg = INTRES.getLocalizedMessage("hardtoken.viewedpuk", tokensn);
          final Map<String, Object> detailspuk =
              new LinkedHashMap<String, Object>();
          detailspuk.put("msg", msg);
          auditSession.log(
              EjbcaEventTypes.HARDTOKEN_VIEWEDPUK,
              EventStatus.SUCCESS,
              EjbcaModuleTypes.HARDTOKEN,
              EjbcaServiceTypes.EJBCA,
              admin.toString(),
              String.valueOf(caid),
              null,
              htd.getUsername(),
              detailspuk);
        }
      }
    }
    LOG.trace("<getHardToken()");
    return returnval;
  }

  @Override
  public Collection<HardTokenInformation> getHardTokens(
      final AuthenticationToken admin,
      final String username,
      final boolean includePUK) {
    if (LOG.isTraceEnabled()) {
      LOG.trace("<getHardToken(username :" + username + ")");
    }
    final ArrayList<HardTokenInformation> returnval =
        new ArrayList<HardTokenInformation>();
    final Collection<HardTokenData> result =
        HardTokenData.findByUsername(entityManager, username);
    for (HardTokenData htd : result) {
      // Find Copyof
      String copyof = null;
      HardTokenPropertyData htpd =
          HardTokenPropertyData.findByProperty(
              entityManager,
              htd.getTokenSN(),
              HardTokenPropertyData.PROPERTY_COPYOF);
      if (htpd != null) {
        copyof = htpd.getValue();
      }
      ArrayList<String> copies = null;
      if (copyof == null) {
        // Find Copies
        Collection<HardTokenPropertyData> copieslocal =
            HardTokenPropertyData.findIdsByPropertyAndValue(
                entityManager,
                HardTokenPropertyData.PROPERTY_COPYOF,
                htd.getTokenSN());
        if (copieslocal.size() > 0) {
          copies = new ArrayList<String>();
          Iterator<HardTokenPropertyData> iter = copieslocal.iterator();
          while (iter.hasNext()) {
            copies.add(iter.next().getId());
          }
        }
      }
      returnval.add(
          new HardTokenInformation(
              htd.getTokenSN(),
              htd.getUsername(),
              htd.getCreateTime(),
              htd.getModifyTime(),
              htd.getTokenType(),
              htd.getSignificantIssuerDN(),
              getHardToken(
                  admin,
                  ((GlobalConfiguration)
                          globalConfigurationSession.getCachedConfiguration(
                              GlobalConfiguration.GLOBAL_CONFIGURATION_ID))
                      .getHardTokenEncryptCA(),
                  includePUK,
                  htd.getData()),
              copyof,
              copies));
      int caid = htd.getSignificantIssuerDN().hashCode();
      String msg =
          INTRES.getLocalizedMessage("hardtoken.viewedtoken", htd.getTokenSN());
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.HARDTOKEN_VIEWED,
          EventStatus.SUCCESS,
          EjbcaModuleTypes.HARDTOKEN,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          String.valueOf(caid),
          null,
          htd.getUsername(),
          details);
      if (includePUK) {
        msg =
            INTRES.getLocalizedMessage("hardtoken.viewedpuk", htd.getTokenSN());
        final Map<String, Object> detailspuk =
            new LinkedHashMap<String, Object>();
        detailspuk.put("msg", msg);
        auditSession.log(
            EjbcaEventTypes.HARDTOKEN_VIEWEDPUK,
            EventStatus.SUCCESS,
            EjbcaModuleTypes.HARDTOKEN,
            EjbcaServiceTypes.EJBCA,
            admin.toString(),
            String.valueOf(caid),
            null,
            htd.getUsername(),
            detailspuk);
      }
    }
    Collections.sort(returnval);
    LOG.trace("<getHardToken()");
    return returnval;
  }

  @Override
  public Collection<String> matchHardTokenByTokenSerialNumber(
      final String searchpattern) {
    LOG.trace(">findHardTokenByTokenSerialNumber()");
    GlobalCesecoreConfiguration globalConfiguration =
        (GlobalCesecoreConfiguration)
            globalConfigurationSession.getCachedConfiguration(
                GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
    return HardTokenData.findUsernamesByHardTokenSerialNumber(
        entityManager,
        searchpattern,
        globalConfiguration.getMaximumQueryCount());
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public void addHardTokenCertificateMapping(
      final AuthenticationToken admin,
      final String tokensn,
      final Certificate certificate) {
    String certificatesn = CertTools.getSerialNumberAsString(certificate);
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">addHardTokenCertificateMapping(certificatesn : "
              + certificatesn
              + ", tokensn : "
              + tokensn
              + ")");
    }
    String fp = CertTools.getFingerprintAsString(certificate);
    if (HardTokenCertificateMap.findByCertificateFingerprint(entityManager, fp)
        == null) {
      try {
        entityManager.persist(new HardTokenCertificateMap(fp, tokensn));
        String msg =
            INTRES.getLocalizedMessage(
                "hardtoken.addedtokencertmapping", certificatesn, tokensn);
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        auditSession.log(
            EjbcaEventTypes.HARDTOKEN_ADDCERTMAP,
            EventStatus.SUCCESS,
            EjbcaModuleTypes.HARDTOKEN,
            EjbcaServiceTypes.EJBCA,
            admin.toString(),
            null,
            certificatesn,
            null,
            details);
      } catch (Exception e) {
        String msg =
            INTRES.getLocalizedMessage(
                "hardtoken.erroraddtokencertmapping", certificatesn, tokensn);
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        auditSession.log(
            EjbcaEventTypes.HARDTOKEN_ADDCERTMAP,
            EventStatus.FAILURE,
            EjbcaModuleTypes.HARDTOKEN,
            EjbcaServiceTypes.EJBCA,
            admin.toString(),
            null,
            certificatesn,
            null,
            details);
      }
    } else {
      // Does not exist
      String msg =
          INTRES.getLocalizedMessage(
              "hardtoken.erroraddtokencertmapping", certificatesn, tokensn);
      LOG.info(msg);
    }
    LOG.trace("<addHardTokenCertificateMapping()");
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public void removeHardTokenCertificateMapping(
      final AuthenticationToken admin, final Certificate certificate) {
    final String certificatesn = CertTools.getSerialNumberAsString(certificate);
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">removeHardTokenCertificateMapping(Certificatesn: "
              + certificatesn
              + ")");
    }
    try {
      final HardTokenCertificateMap htcm =
          HardTokenCertificateMap.findByCertificateFingerprint(
              entityManager, CertTools.getFingerprintAsString(certificate));
      if (htcm == null) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Trying to remove HardTokenCertificateMap that does not exist: "
                  + CertTools.getFingerprintAsString(certificate));
        }
      } else {
        entityManager.remove(htcm);
        final String msg =
            INTRES.getLocalizedMessage(
                "hardtoken.removedtokencertmappingcert", certificatesn);
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        auditSession.log(
            EjbcaEventTypes.HARDTOKEN_REMOVECERTMAP,
            EventStatus.SUCCESS,
            EjbcaModuleTypes.HARDTOKEN,
            EjbcaServiceTypes.EJBCA,
            admin.toString(),
            null,
            certificatesn,
            null,
            details);
      }
    } catch (Exception e) {
      final String msg =
          INTRES.getLocalizedMessage(
              "hardtoken.errorremovetokencertmappingcert", certificatesn);
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.HARDTOKEN_REMOVECERTMAP,
          EventStatus.FAILURE,
          EjbcaModuleTypes.HARDTOKEN,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          certificatesn,
          null,
          details);
    }
    LOG.trace("<removeHardTokenCertificateMapping()");
  }

  /**
   * Removes all mappings between a hard token and a certificate.
   *
   * @param admin the administrator calling the function
   * @param tokensn the serial number to remove.
   */
  private void removeHardTokenCertificateMappings(
      final AuthenticationToken admin, final String tokensn) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">removeHardTokenCertificateMappings(tokensn: " + tokensn + ")");
    }
    try {
      Iterator<HardTokenCertificateMap> result =
          HardTokenCertificateMap.findByTokenSN(entityManager, tokensn)
              .iterator();
      while (result.hasNext()) {
        HardTokenCertificateMap htcm = result.next();
        entityManager.remove(htcm);
      }
      String msg =
          INTRES.getLocalizedMessage(
              "hardtoken.removedtokencertmappingtoken", tokensn);
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.HARDTOKEN_REMOVECERTMAP,
          EventStatus.SUCCESS,
          EjbcaModuleTypes.HARDTOKEN,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          null,
          null,
          details);
    } catch (Exception e) {
      String msg =
          INTRES.getLocalizedMessage(
              "hardtoken.errorremovetokencertmappingtoken", tokensn);
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.HARDTOKEN_REMOVECERTMAP,
          EventStatus.FAILURE,
          EjbcaModuleTypes.HARDTOKEN,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          null,
          null,
          details);
    }
    LOG.trace("<removeHardTokenCertificateMappings()");
  }

  @Override
  public Collection<Certificate> findCertificatesInHardToken(
      final String tokensn) {
    if (LOG.isTraceEnabled()) {
      LOG.trace("<findCertificatesInHardToken(tokensn :" + tokensn + ")");
    }
    final List<Certificate> ret = new ArrayList<Certificate>();
    for (final CertificateDataWrapper cdw
        : getCertificateDatasFromHardToken(tokensn)) {
      ret.add(cdw.getCertificate());
    }
    LOG.trace("<findCertificatesInHardToken()");
    return ret;
  }

  @Override
  public List<CertificateDataWrapper> getCertificateDatasFromHardToken(
      final String tokensn) {
    final List<CertificateDataWrapper> ret =
        new ArrayList<CertificateDataWrapper>();
    try {
      for (final HardTokenCertificateMap htcm
          : HardTokenCertificateMap.findByTokenSN(entityManager, tokensn)) {
        final CertificateDataWrapper cdw =
            certificateStoreSession.getCertificateData(
                htcm.getCertificateFingerprint());
        if (cdw != null) {
          ret.add(cdw);
        }
      }
    } catch (Exception e) {
      throw new EJBException(e);
    }
    return ret;
  }

  @Override
  public String findHardTokenByCertificateSNIssuerDN(
      final BigInteger certificatesn, final String issuerdn) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          "<findHardTokenByCertificateSNIssuerDN(certificatesn :"
              + certificatesn
              + ", issuerdn :"
              + issuerdn
              + ")");
    }
    String returnval = null;
    X509Certificate cert =
        (X509Certificate)
            certificateStoreSession.findCertificateByIssuerAndSerno(
                issuerdn, certificatesn);
    if (cert != null) {
      HardTokenCertificateMap htcm =
          HardTokenCertificateMap.findByCertificateFingerprint(
              entityManager, CertTools.getFingerprintAsString(cert));
      if (htcm != null) {
        returnval = htcm.getTokenSN();
      }
    }
    LOG.trace("<findHardTokenByCertificateSNIssuerDN()");
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public void tokenGenerated(
      final AuthenticationToken admin,
      final String tokensn,
      final String username,
      final String significantissuerdn) {
    int caid = CertTools.stringToBCDNString(significantissuerdn).hashCode();
    try {
      String msg =
          INTRES.getLocalizedMessage("hardtoken.generatedtoken", tokensn);
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.HARDTOKEN_GENERATE,
          EventStatus.SUCCESS,
          EjbcaModuleTypes.HARDTOKEN,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          String.valueOf(caid),
          null,
          username,
          details);
    } catch (Exception e) {
      throw new EJBException(e);
    }
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public void errorWhenGeneratingToken(
      final AuthenticationToken admin,
      final String tokensn,
      final String username,
      final String significantissuerdn) {
    int caid = CertTools.stringToBCDNString(significantissuerdn).hashCode();
    try {
      String msg =
          INTRES.getLocalizedMessage("hardtoken.errorgeneratetoken", tokensn);
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.HARDTOKEN_GENERATE,
          EventStatus.FAILURE,
          EjbcaModuleTypes.HARDTOKEN,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          String.valueOf(caid),
          null,
          username,
          details);
    } catch (Exception e) {
      throw new EJBException(e);
    }
  }

  @Override
  public List<String> getHardTokenProfileUsingCertificateProfile(
      final int certificateProfileId) {
    List<String> result = new ArrayList<String>();
    Collection<Integer> certprofiles = null;
    HardTokenProfile profile = null;
    for (HardTokenProfileData profileData
        : HardTokenProfileData.findAll(entityManager)) {
      profile = getHardTokenProfile(profileData);
      if (profile instanceof EIDProfile) {
        certprofiles = ((EIDProfile) profile).getAllCertificateProfileIds();
        if (certprofiles.contains(certificateProfileId)) {
          result.add(profileData.getName());
        }
      }
    }
    return result;
  }

  @Override
  public boolean existsHardTokenProfileInHardTokenIssuer(final int id) {
    HardTokenIssuer issuer = null;
    Collection<Integer> hardtokenissuers = null;
    boolean exists = false;
    Collection<HardTokenIssuerData> result =
        HardTokenIssuerData.findAll(entityManager);
    Iterator<HardTokenIssuerData> i = result.iterator();
    while (i.hasNext() && !exists) {
      issuer = i.next().getHardTokenIssuer();
      hardtokenissuers = issuer.getAvailableHardTokenProfiles();
      if (hardtokenissuers.contains(Integer.valueOf(id))) {
        exists = true;
      }
    }
    return exists;
  }

  private int findFreeHardTokenProfileId() {
    final ProfileID.DB db =
        new ProfileID.DB() {
          @Override
          public boolean isFree(final int i) {
            return HardTokenProfileData.findByPK(
                    entityManager, Integer.valueOf(i))
                == null;
          }
        };
    return ProfileID.getNotUsedID(db);
  }

  private int findFreeHardTokenIssuerId() {
    final ProfileID.DB db =
        new ProfileID.DB() {
          @Override
          public boolean isFree(final int i) {
            return HardTokenIssuerData.findByPK(
                    entityManager, Integer.valueOf(i))
                == null;
          }
        };
    return ProfileID.getNotUsedID(db);
  }

  /**
   * Method that returns the hard token data from a hashmap and updates it if
   * necessary.
   *
   * @param admin Admin
   * @param encryptcaid ID
   * @param includePUK PUK
   * @param odata data
   * @return token
   */
  private HardToken getHardToken(
      final AuthenticationToken admin,
      final int encryptcaid,
      final boolean includePUK,
      final Map<?, ?> odata) {
    HardToken returnval = null;
    Map<?, ?> data = odata;
    if (data.get(HardTokenData.ENCRYPTEDDATA) != null) {
      // Data in encrypted, decrypt
      byte[] encdata = (byte[]) data.get(HardTokenData.ENCRYPTEDDATA);

      HardTokenEncryptCAServiceRequest request =
          new HardTokenEncryptCAServiceRequest(
              HardTokenEncryptCAServiceRequest.COMMAND_DECRYPTDATA, encdata);
      try {
        HardTokenEncryptCAServiceResponse response =
            (HardTokenEncryptCAServiceResponse)
                caAdminSession.extendedService(admin, encryptcaid, request);
        ObjectInputStream ois =
            new ObjectInputStream(new ByteArrayInputStream(response.getData()));
        data = (Map<?, ?>) ois.readObject();
      } catch (Exception e) {
        throw new EJBException(e);
      }
    }

    int tokentype = ((Integer) data.get(HardToken.TOKENTYPE)).intValue();

    switch (tokentype) {
      case SecConst.TOKEN_SWEDISHEID:
        returnval = new SwedishEIDHardToken(includePUK);
        break;
      case SecConst.TOKEN_ENHANCEDEID:
        returnval = new EnhancedEIDHardToken(includePUK);
        break;
      case SecConst.TOKEN_TURKISHEID:
        returnval = new TurkishEIDHardToken(includePUK);
        break;
      case SecConst.TOKEN_EID: // Left for backward compability
        returnval = new EIDHardToken(includePUK);
        break;
      default:
        returnval = new EIDHardToken(includePUK);
        break;
    }

    returnval.loadData(data);
    return returnval;
  }

  /**
   * Method that saves the hard token issuer data to a HashMap that can be saved
   * to database.
   *
   * @param admin Admin
   * @param encryptcaid ID
   * @param tokendata Data
   * @return Map
   */
  @SuppressWarnings("unchecked")
  private LinkedHashMap<String, byte[]> setHardToken(
      final AuthenticationToken admin,
      final int encryptcaid,
      final HardToken tokendata) {
    LinkedHashMap<String, byte[]> retval = null;
    if (encryptcaid != 0) {
      try {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream ois = new ObjectOutputStream(baos);
        ois.writeObject(tokendata.saveData());
        HardTokenEncryptCAServiceRequest request =
            new HardTokenEncryptCAServiceRequest(
                HardTokenEncryptCAServiceRequest.COMMAND_ENCRYPTDATA,
                baos.toByteArray());
        HardTokenEncryptCAServiceResponse response =
            (HardTokenEncryptCAServiceResponse)
                caAdminSession.extendedService(admin, encryptcaid, request);
        LinkedHashMap<String, byte[]> data =
            new LinkedHashMap<String, byte[]>();
        data.put(HardTokenData.ENCRYPTEDDATA, response.getData());
        retval = data;
      } catch (Exception e) {
        throw new EJBException(e);
      }
    } else {
      // Don't encrypt data
      retval = (LinkedHashMap<String, byte[]>) tokendata.saveData();
    }
    return retval;
  }

  private HardTokenProfile getHardTokenProfile(
      final HardTokenProfileData htpData) {
    HardTokenProfile profile = null;
    java.beans.XMLDecoder decoder;
    try {
      decoder =
          new java.beans.XMLDecoder(
              new java.io.ByteArrayInputStream(
                  htpData.getData().getBytes("UTF8")));
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
    final Map<?, ?> h = (Map<?, ?>) decoder.readObject();
    decoder.close();
    // Handle Base64 encoded string values
    final Map<?, ?> data = new Base64GetHashMap(h);
    switch (((Integer) (data.get(HardTokenProfile.TYPE))).intValue()) {
      case SwedishEIDProfile.TYPE_SWEDISHEID:
        profile = new SwedishEIDProfile();
        break;
      case EnhancedEIDProfile.TYPE_ENHANCEDEID:
        profile = new EnhancedEIDProfile();
        break;
      case TurkishEIDProfile.TYPE_TURKISHEID:
        profile = new TurkishEIDProfile();
        break;
      default: break;
    }
    profile.loadData(data);
    return profile;
  }
}
