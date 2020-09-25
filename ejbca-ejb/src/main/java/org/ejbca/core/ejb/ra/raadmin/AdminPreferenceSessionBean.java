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

package org.ejbca.core.ejb.ra.raadmin;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

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
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.config.RaStyleInfo;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ra.raadmin.AdminPreference;

/**
 * Stores data used by web server clients.
 * 
 * @version $Id: RaAdminSessionBean.java 9579 2010-07-30 18:07:23Z jeklund$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AdminPreferenceSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AdminPreferenceSessionBean implements AdminPreferenceSessionLocal, AdminPreferenceSessionRemote {

    private static final String DEFAULTUSERPREFERENCE = "default";

    private static final Logger log = Logger.getLogger(AdminPreferenceSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    @EJB
    private RaStyleCacheBean raStyleCacheBean;

    @Override
    public AdminPreference getAdminPreference(final String certificatefingerprint) {
        if (log.isTraceEnabled()) {
            log.trace(">getAdminPreference()");
        }
        AdminPreference ret = null;
        if (certificatefingerprint != null) {
            AdminPreferencesData adminPreferencesData = AdminPreferencesData.findById(entityManager, certificatefingerprint);
            if (adminPreferencesData != null) {
                ret = adminPreferencesData.getAdminPreference();
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<getAdminPreference()");
        }
        return ret;
    }
    
    @Override
    public Map<String, AdminPreference> getAdminPreferences() {
        if (log.isTraceEnabled()) {
            log.trace(">getAdminPreference()");
        }        
        HashMap<String, AdminPreference> adminPreferences = new HashMap<>();
        final List<AdminPreferencesData> adminPreferencesData = AdminPreferencesData.findAll(entityManager);
        
        if (adminPreferencesData != null && !adminPreferencesData.isEmpty()) {
            for(final AdminPreferencesData adminPreferenceData : adminPreferencesData) {
                adminPreferences.put(adminPreferenceData.getId(), adminPreferenceData.getAdminPreference());
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<getAdminPreference()");
        }        
        return adminPreferences;
    }

    @Override
    public boolean addAdminPreference(final X509CertificateAuthenticationToken admin, final AdminPreference adminpreference) {
        String certificatefingerprint = CertTools.getFingerprintAsString(admin.getCertificate());
        if (log.isTraceEnabled()) {
            log.trace(">addAdminPreference(fingerprint : " + certificatefingerprint + ")");
        }
        boolean ret = false;
        // EJB 2.1 only?: We must actually check if there is one before we try
        // to add it, because wls does not allow us to catch any errors if
        // creating fails, that sux
       
        if (AdminPreferencesData.findById(entityManager, certificatefingerprint) == null) {
            try {
                AdminPreferencesData apdata = new AdminPreferencesData(certificatefingerprint, adminpreference);
                entityManager.persist(apdata);
                String msg = intres.getLocalizedMessage("ra.adminprefadded", apdata.getId());
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.RA_ADDADMINPREF, EventStatus.SUCCESS, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
                ret = true;
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("ra.adminprefexists");
                log.info(msg, e);
            }
        } else {
            String msg = intres.getLocalizedMessage("ra.adminprefexists");
            log.info(msg);
        }
        log.trace("<addAdminPreference()");
        return ret;
    }

    @Override
    public boolean changeAdminPreference(final X509CertificateAuthenticationToken admin, final AdminPreference adminpreference) {
        return updateAdminPreference(admin, adminpreference, true);
    }

    @Override
    public boolean changeAdminPreferenceNoLog(final X509CertificateAuthenticationToken admin, final AdminPreference adminpreference) {
        return updateAdminPreference(admin, adminpreference, false);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean existsAdminPreference(final String certificatefingerprint) {
        if (log.isTraceEnabled()) {
            log.trace(">existsAdminPreference(fingerprint : " + certificatefingerprint + ")");
        }
        boolean ret = false;
        if (certificatefingerprint!=null) {
            final AdminPreferencesData adminPreferencesData = AdminPreferencesData.findById(entityManager, certificatefingerprint);
            if (adminPreferencesData != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Found admin preferences with id " + adminPreferencesData.getId());
                }
                ret = true;
            }
        }
        log.trace("<existsAdminPreference()");
        return ret;
    }

    @Override
    public RaStyleInfo getPreferedRaStyleInfo(AuthenticationToken admin) {
        List<RaStyleInfo> availableRaStyles = getAvailableRaStyleInfos(admin);
        Integer preferedStyleId = getCurrentRaStyleId(admin);
        // Administrator hasn't set a preferred style. Use first available
        if (preferedStyleId == null && !availableRaStyles.isEmpty()) {
            return availableRaStyles.get(0);
        }
        // Default style will be used
        if (availableRaStyles.isEmpty() || preferedStyleId == 0) {
            return null;
        }
        
        // Return the style preferred by administrator
        for (RaStyleInfo rastyle : availableRaStyles) {
            if (preferedStyleId == rastyle.getArchiveId()) {
                return rastyle;
            }
        }
        
        // Previously set preference is no longer available, return first available.
        return availableRaStyles.get(0);
    }
    
    @Override
    public List<RaStyleInfo> getAvailableRaStyleInfos(AuthenticationToken admin) {
        return raStyleCacheBean.getAvailableRaStyles(admin);
    }

    @Override
    public void invalidateRaStyleCache() {
        raStyleCacheBean.invalidateCache();
    }
    
    @Override
    public AdminPreference getDefaultAdminPreference() {
        if (log.isTraceEnabled()) {
            log.trace(">getDefaultAdminPreference()");
        }
        AdminPreference ret = null;
        AdminPreferencesData apdata = AdminPreferencesData.findById(entityManager, DEFAULTUSERPREFERENCE);
        if (apdata != null) {
            ret = apdata.getAdminPreference();
        } else {
            try {
                // Create new configuration
                AdminPreferencesData newapdata = new AdminPreferencesData(DEFAULTUSERPREFERENCE, new AdminPreference());
                entityManager.persist(newapdata);
                ret = newapdata.getAdminPreference();
            } catch (Exception e) {
                throw new EJBException(e);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<getDefaultAdminPreference()");
        }
        return ret;
    }

    @Override
    public void saveDefaultAdminPreference(final AuthenticationToken admin, final AdminPreference defaultadminpreference)
            throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">saveDefaultAdminPreference()");
        }

        if (!authorizationSession.isAuthorized(admin, StandardRules.SYSTEMCONFIGURATION_EDIT.resource())) {
            String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", StandardRules.SYSTEMCONFIGURATION_EDIT, null);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.RA_DEFAULTADMINPREF, EventStatus.FAILURE, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);
            throw new AuthorizationDeniedException(msg);
        }

        AdminPreferencesData apdata = AdminPreferencesData.findById(entityManager, DEFAULTUSERPREFERENCE);
        if (apdata != null) {
            final Map<Object, Object> diff = apdata.getAdminPreference().diff(defaultadminpreference);
            apdata.setAdminPreference(defaultadminpreference);
            final String msg = intres.getLocalizedMessage("ra.defaultadminprefsaved");
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            for (Map.Entry<Object, Object> entry : diff.entrySet()) {
                details.put(entry.getKey().toString(), entry.getValue().toString());
            }
            auditSession.log(EjbcaEventTypes.RA_DEFAULTADMINPREF, EventStatus.SUCCESS, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);
        } else {
            final String msg = intres.getLocalizedMessage("ra.errorsavedefaultadminpref");
            log.info(msg);
            throw new EJBException(msg);
        }
        if (log.isTraceEnabled()) {
            log.trace("<saveDefaultAdminPreference()");
        }
    }

    /**
     * Changes the admin preference in the database. Returns false if admin
     * preference doesn't exist.
     */
    private boolean updateAdminPreference(X509CertificateAuthenticationToken admin, AdminPreference adminpreference, boolean dolog) {
        String certificatefingerprint = CertTools.getFingerprintAsString(admin.getCertificate());
        if (log.isTraceEnabled()) {
            log.trace(">updateAdminPreference(fingerprint : " + certificatefingerprint + ")");
        }
        boolean ret = false;
        AdminPreferencesData apdata1 = AdminPreferencesData.findById(entityManager, certificatefingerprint);
        if (apdata1 != null) {
            final Map<Object, Object> diff = apdata1.getAdminPreference().diff(adminpreference);
            apdata1.setAdminPreference(adminpreference);
            // Earlier we used to remove and re-add the adminpreferences data
            // I don't know why, but that did not work on Oracle AS, so lets
            // just do what create does, and setAdminPreference.
            /*
             * adminpreferenceshome.remove(certificatefingerprint); try{
             * AdminPreferencesDataLocal apdata2 =
             * adminpreferenceshome.findByPrimaryKey(certificatefingerprint);
             * debug("Found admin preferences with id: "+apdata2.getId()); }
             * catch (javax.ejb.FinderException fe) {
             * debug("Admin preferences has been removed: "
             * +certificatefingerprint); }
             * adminpreferenceshome.create(certificatefingerprint
             * ,adminpreference); try{ AdminPreferencesDataLocal apdata3 =
             * adminpreferenceshome.findByPrimaryKey(certificatefingerprint);
             * debug("Found admin preferences with id: "+apdata3.getId()); }
             * catch (javax.ejb.FinderException fe) {
             * error("Admin preferences was not created: "
             * +certificatefingerprint); }
             */
            if (dolog) {
                final String msg = intres.getLocalizedMessage("ra.changedadminpref", certificatefingerprint);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                for (Map.Entry<Object, Object> entry : diff.entrySet()) {
                    details.put(entry.getKey().toString(), entry.getValue().toString());
                }
                auditSession.log(EjbcaEventTypes.RA_EDITADMINPREF, EventStatus.SUCCESS, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
            }
            ret = true;
        } else {
            ret = false;
            if (dolog) {
                final String msg = intres.getLocalizedMessage("ra.adminprefnotfound", certificatefingerprint);
                log.info(msg);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<updateAdminPreference()");
        }
        return ret;
    }

    @Override
    public Integer getCurrentRaStyleId(AuthenticationToken admin) {
        
        if (!(admin instanceof X509CertificateAuthenticationToken)) {
            return null;
        }

        String certificatefingerprint = CertTools.getFingerprintAsString(((X509CertificateAuthenticationToken) admin).getCertificate());

        AdminPreference adminPreference = getAdminPreference(certificatefingerprint);

        if (adminPreference == null) {
            return null;
        }

        Integer currentStyleId = adminPreference.getPreferedRaStyleId();

        if (currentStyleId != null) {
            return currentStyleId;
        }
        return null;

    }

    @Override
    public void setCurrentRaStyleId(int currentStyleId, AuthenticationToken admin) {
        
        String certificatefingerprint = CertTools.getFingerprintAsString(((X509CertificateAuthenticationToken) admin).getCertificate());

        AdminPreference adminPreference = getAdminPreference(certificatefingerprint);
        
        adminPreference.setPreferedRaStyleId(currentStyleId);
        updateAdminPreference((X509CertificateAuthenticationToken) admin, adminPreference, false);
        
    }

    @Override
    public Locale getCurrentRaLocale(AuthenticationToken admin) {
        
        if (!(admin instanceof X509CertificateAuthenticationToken)) {
            return null;
        }

        String certificatefingerprint = CertTools.getFingerprintAsString(((X509CertificateAuthenticationToken) admin).getCertificate());

        AdminPreference adminPreference = getAdminPreference(certificatefingerprint);

        if (adminPreference == null) {
            return getDefaultAdminPreference().getPreferedRaLanguage();
        }

        Locale currentLocale = adminPreference.getPreferedRaLanguage();

        if (currentLocale != null) {
            return currentLocale;
        }

        return getDefaultAdminPreference().getPreferedRaLanguage();
    }

    @Override
    public void setCurrentRaLocale(Locale locale, AuthenticationToken admin) {
        
        String certificatefingerprint = CertTools.getFingerprintAsString(((X509CertificateAuthenticationToken) admin).getCertificate());
        
        AdminPreference adminPreference = getAdminPreference(certificatefingerprint);
        
        adminPreference.setPreferedRaLanguage(locale);
        updateAdminPreference((X509CertificateAuthenticationToken) admin, adminPreference, false);
        
    }

}
