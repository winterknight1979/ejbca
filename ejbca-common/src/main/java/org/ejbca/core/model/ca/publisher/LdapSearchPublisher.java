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

package org.ejbca.core.model.ca.publisher;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.util.TCPTool;

/**
 * @version $Id: LdapSearchPublisher.java 22117 2015-10-29 10:53:42Z mikekushner
 *     $
 */
public class LdapSearchPublisher extends LdapPublisher {

  private static final long serialVersionUID = -4593116897226605008L;
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(LdapSearchPublisher.class);
  /** Internal localization of logs and errors. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();

  // Default Values
  /** Comfig. */
  protected static final String SEARCHBASEDN = "searchbasedn";
  /** Comfig. */
  protected static final String SEARCHFILTER = "searchfilter";

  /** constructor.*/
  public LdapSearchPublisher() {
    super();
    data.put(TYPE, Integer.valueOf(PublisherConst.TYPE_LDAPSEARCHPUBLISHER));

    setSearchBaseDN("");
    setSearchFilter("");

    // By default the LDAP search publisher should not modify any attributes
    // except the certificate
    setModifyExistingAttributes(false);
    setAddNonExistingAttributes(false);
  }

  // Public Methods

  private static String getPartFromDN(
      final String certDN, final String userDN, final String dnpart) {
    final String certResult = CertTools.getPartFromDN(certDN, dnpart);
    if (certResult != null) {
      return certResult;
    }
    return CertTools.getPartFromDN(userDN, dnpart);
  }
  /**
   * SearchOldEntity is the only method differing between regular ldap and ldap
   * search publishers. Apart from how they find existing users, the publishing
   * works the same.
   *
   * @param username user
   * @param ldapVersion version
   * @param lc conn
   * @param certDN the DN from the certificate, can be used to extract search
   *     information or a LDAP DN
   * @param userDN DN
   * @param email mail
   * @throws PublisherException fail
   * @return an existing LDAPEntry, or null if not found
   */
  protected LDAPEntry searchOldEntity(
      final String username,
      final int ldapVersion,
      final LDAPConnection lc,
      final String certDN,
      final String userDN,
      final String email)
      throws PublisherException {
    LDAPEntry oldEntry = null; // return value

    // Try all the listed servers
    Iterator<String> servers = getHostnameList().iterator();
    boolean connectionFailed;
    do {
      connectionFailed = false;
      String currentServer = servers.next();
      // PARTE 1: Search for an existing entry in the LDAP directory
      //  If it exists, this will be returned to be populated
      //  if not exist, nothing will be returned and a new LDAP entry created
      try {
        TCPTool.probeConnectionLDAP(
            currentServer,
            Integer.parseInt(getPort()),
            getConnectionTimeOut()); // Avoid waiting for halfdead-servers
        // connect to the server
        LOG.debug("Connecting to " + currentServer);
        lc.connect(currentServer, Integer.parseInt(getPort()));
        // Execute a STARTTLS handshake if it was requested.
        if (getConnectionSecurity() == ConnectionSecurity.STARTTLS) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("STARTTLS to LDAP server " + currentServer);
          }
          lc.startTLS();
        }

        // authenticate to the server
        LOG.debug("Logging in with BIND DN " + getLoginDN());
        lc.bind(
            ldapVersion,
            getLoginDN(),
            getLoginPassword().getBytes("UTF8"),
            ldapBindConstraints);
        // searchFilter = "(&(objectclass=person)(uid=" + username + "))";
        String searchFilter = getSearchFilter();
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Compiling search filter: "
                  + searchFilter
                  + ", from certDN '"
                  + certDN
                  + "' and userDN '"
                  + userDN
                  + "'.");
        }
        if (username != null) {
          Pattern user =
              Pattern.compile("\\$USERNAME", Pattern.CASE_INSENSITIVE);
          searchFilter = user.matcher(searchFilter).replaceAll(username);
        }
        if (email != null) {
          Pattern eMail = Pattern.compile("\\$EMAIL", Pattern.CASE_INSENSITIVE);
          searchFilter = eMail.matcher(searchFilter).replaceAll(email);
        }
        if (getPartFromDN(certDN, userDN, "CN") != null) {
          Pattern cn = Pattern.compile("\\$CN", Pattern.CASE_INSENSITIVE);
          searchFilter =
              cn.matcher(searchFilter)
                  .replaceAll(getPartFromDN(certDN, userDN, "CN"));
        }
        if (getPartFromDN(certDN, userDN, "O") != null) {
          Pattern o = Pattern.compile("\\$O", Pattern.CASE_INSENSITIVE);
          searchFilter =
              o.matcher(searchFilter)
                  .replaceAll(getPartFromDN(certDN, userDN, "O"));
        }
        if (getPartFromDN(certDN, userDN, "OU") != null) {
          Pattern ou = Pattern.compile("\\$OU", Pattern.CASE_INSENSITIVE);
          searchFilter =
              ou.matcher(searchFilter)
                  .replaceAll(getPartFromDN(certDN, userDN, "OU"));
        }
        if (getPartFromDN(certDN, userDN, "C") != null) {
          Pattern c = Pattern.compile("\\$C", Pattern.CASE_INSENSITIVE);
          searchFilter =
              c.matcher(searchFilter)
                  .replaceAll(getPartFromDN(certDN, userDN, "C"));
        }
        if (getPartFromDN(certDN, userDN, "UID") != null) {
          Pattern c = Pattern.compile("\\$UID", Pattern.CASE_INSENSITIVE);
          searchFilter =
              c.matcher(searchFilter)
                  .replaceAll(getPartFromDN(certDN, userDN, "UID"));
        }
        LOG.debug("Resulting search filter '" + searchFilter + "'.");
        LOG.debug(
            "Making SRCH with BaseDN '"
                + getSearchBaseDN()
                + "' and filter '"
                + searchFilter
                + "'.");
        String searchbasedn = getSearchBaseDN();
        int searchScope = LDAPConnection.SCOPE_SUB;
        String[] attrs = {LDAPConnection.NO_ATTRS};
        boolean attributeTypesOnly = true;
        LDAPSearchResults searchResults =
            lc.search(
                searchbasedn, // container to search
                searchScope, // search scope
                searchFilter, // search filter
                attrs, // "1.1" returns entry name only
                attributeTypesOnly,
                ldapSearchConstraints); // no attribute values are returned
        // try to read the old object
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "serachResults contains entries: " + searchResults.hasMore());
        }
        final String ldapDN;
        if (searchResults.hasMore()) {
          oldEntry = searchResults.next();
          ldapDN = oldEntry.getDN();
          if (searchResults.hasMore()) {
            LOG.debug(
                "Found more than one matches with filter '"
                    + searchFilter
                    + "'. Using the first match with LDAP entry with DN: "
                    + oldEntry.getDN());
          } else {
            LOG.debug(
                "Found one match with filter: '"
                    + searchFilter
                    + "', match with DN: "
                    + oldEntry.getDN());
          }
        } else {
          ldapDN = constructLDAPDN(certDN, userDN);
          LOG.debug(
              "No matches found using filter: '"
                  + searchFilter
                  + "'. Using DN: "
                  + ldapDN);
        }
        // try to read the old object
        try {
          oldEntry = lc.read(ldapDN, ldapSearchConstraints);
        } catch (LDAPException e) {
          if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
            String msg =
                INTRES.getLocalizedMessage("publisher.noentry", ldapDN);
            LOG.info(msg);
          } else {
            String msg =
                INTRES.getLocalizedMessage("publisher.infoexists", ldapDN);
            LOG.info(msg);
          }
        }
      } catch (LDAPException e) {
        if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
          String msg =
              INTRES.getLocalizedMessage(
                  "publisher.noentry", certDN + ", " + userDN);
          LOG.info(msg);
        } else {
          connectionFailed = true;
          if (servers.hasNext()) {
            LOG.debug(
                "Failed to publish to "
                    + currentServer
                    + ". Trying next in list.");
          } else {
            String msg =
                INTRES.getLocalizedMessage(
                    "publisher.errorldapbind", e.getMessage());
            LOG.error(msg, e);
            throw new PublisherException(msg);
          }
        }
      } catch (UnsupportedEncodingException e) {
        String msg =
            INTRES.getLocalizedMessage(
                "publisher.errorpassword", getLoginPassword());
        throw new PublisherException(msg);
      } finally {
        // disconnect with the server
        try {
          lc.disconnect(ldapDisconnectConstraints);
        } catch (LDAPException e) {
          String msg = INTRES.getLocalizedMessage("publisher.errordisconnect");
          LOG.error(msg, e);
        }
      }
    } while (connectionFailed && servers.hasNext());
    return oldEntry;
  }

  /** @return search base DN */
  public String getSearchBaseDN() {
    return (String) data.get(SEARCHBASEDN);
  }

  /**
   * Set search base DN.
   *
   * @param searchbasedn DN
   */
  public void setSearchBaseDN(final String searchbasedn) {
    data.put(SEARCHBASEDN, searchbasedn);
  }

  /** @return LDAP search filter string */
  public String getSearchFilter() {
    return (String) data.get(SEARCHFILTER);
  }

  /**
   * Sets LDAP search filter string.
   *
   * @param searchfilter Filter
   */
  public void setSearchFilter(final String searchfilter) {
    data.put(SEARCHFILTER, searchfilter);
  }

  // Private methods

  /**
   * @return clone
   * @throws CloneNotSupportedException fail
   * @see org.ejbca.core.model.ca.publisher.BasePublisher#clone() */
  @SuppressWarnings({"unchecked", "rawtypes"})
  public Object clone() throws CloneNotSupportedException {
    LdapSearchPublisher clone = new LdapSearchPublisher();
    HashMap clonedata = (HashMap) clone.saveData();

    Iterator<Object> i = (data.keySet()).iterator();
    while (i.hasNext()) {
      Object key = i.next();
      clonedata.put(key, data.get(key));
    }

    clone.loadData(clonedata);
    return clone;
  }
}
