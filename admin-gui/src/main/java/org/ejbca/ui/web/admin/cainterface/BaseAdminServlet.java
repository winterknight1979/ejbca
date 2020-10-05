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

import java.beans.Beans;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.ui.web.admin.cainterface.exception.AdminWebAuthenticationException;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.admin.rainterface.RAInterfaceBean;

/**
 * Base servlet class for all AdminWeb pages that require authentication.
 * 
 * @version $Id: BaseAdminServlet.java 34154 2019-12-23 13:38:17Z samuellb $
 */
public abstract class BaseAdminServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(BaseAdminServlet.class);

    @EJB
    private WebAuthenticationProviderSessionLocal authenticationSession;
    
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {
            CryptoProviderTools.installBCProvider(); // Install BouncyCastle provider
        } catch (Exception e) {
            throw new ServletException(e);
        }
        if (authenticationSession == null) {
            log.error("Local EJB injection failed of AuthenticationSession");
        }
    }
    
    /**
     * Authenticates the client using it's X.509 certificate.
     * @param request Servlet request
     * @param response Servlet response
     * @param accessResources Resources
     * @return AuthenticationToken from  AuthenticationSessionLocal. Never null.
     * @throws AdminWebAuthenticationException Fail 
     * @throws ServletException Fail
     */
    protected AuthenticationToken authenticateAdmin(HttpServletRequest request, HttpServletResponse response, final String... accessResources) throws AdminWebAuthenticationException, ServletException {
        // Check if authorized
        EjbcaWebBean ejbcawebbean = getEjbcaWebBean(request);
        try {
            ejbcawebbean.initialize(request, accessResources);
        } catch (Exception e) {
            log.info("Could not initialize for client " + request.getRemoteAddr());
            log.debug("Client initialization failed", e);
            throw new AdminWebAuthenticationException("Authorization Denied");
        }

        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        if (certs == null) {
            log.info("Client " + request.getRemoteAddr() + " was denied. No client certificate sent.");
            throw new AdminWebAuthenticationException("This servlet requires certificate authentication!");
        }

        final Set<X509Certificate> credentials = new HashSet<>();
        credentials.add(certs[0]);
        AuthenticationSubject subject = new AuthenticationSubject(null, credentials);
        AuthenticationToken admin = authenticationSession.authenticate(subject);
        if (admin == null) {
            final String message = "Authorization denied for certificate: " + CertTools.getSubjectDN(certs[0]);
            log.info("Client " + request.getRemoteAddr() + " was denied. " + message);
            throw new AdminWebAuthenticationException(message);
        }
        return admin;
    }
    
    /**
     * Gets the RAInterfaceBean object, or creates and initializes a new RAInterfaceBean if not already created.
     * @param req Request
     * @return Bean
     * @throws ServletException Fail
     */
    protected final RAInterfaceBean getRaBean(HttpServletRequest req) throws ServletException {
        HttpSession session = req.getSession();
        RAInterfaceBean rabean = (RAInterfaceBean) session.getAttribute("rabean");
        if (rabean == null) {
            try {
                rabean = (RAInterfaceBean) Beans.instantiate(Thread.currentThread().getContextClassLoader(),
                        org.ejbca.ui.web.admin.rainterface.RAInterfaceBean.class.getName());
            } catch (ClassNotFoundException e) {
                throw new ServletException(e);
            } catch (Exception e) {
                throw new ServletException("Unable to instantiate RAInterfaceBean", e);
            }
            try {
                rabean.initialize(req, getEjbcaWebBean(req));
            } catch (Exception e) {
                throw new ServletException("Cannot initialize RAInterfaceBean", e);
            }
            session.setAttribute("rabean", rabean);
        }
        return rabean;
    }

    /**
     * Gets the EjbcaWebBean object, or creates and initializes a new EjbcaWebBean if not already created.
     * @param req Request
     * @return Bean
     * @throws ServletException Fail
     */
    protected final EjbcaWebBean getEjbcaWebBean(HttpServletRequest req) throws ServletException {
        HttpSession session = req.getSession();
        EjbcaWebBean ejbcawebbean = (EjbcaWebBean) session.getAttribute("ejbcawebbean");
        if (ejbcawebbean == null) {
            try {
                ejbcawebbean = (EjbcaWebBean) java.beans.Beans.instantiate(Thread.currentThread().getContextClassLoader(),
                        EjbcaWebBean.class.getName());
            } catch (ClassNotFoundException exc) {
                throw new ServletException(exc.getMessage());
            } catch (Exception exc) {
                throw new ServletException(" Cannot create bean of class " + EjbcaWebBean.class.getName(), exc);
            }
            session.setAttribute("ejbcawebbean", ejbcawebbean);
        }
        return ejbcawebbean;
    }
    
}
