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
package org.ejbca.core.model.ca.publisher.custpubl1;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import org.ejbca.core.model.ca.publisher.PublisherException;

/**
 * An additional mocked version of the CustomerLdapPublisher1 used by the unit
 * tests.
 *
 * @version $Id: ThirdMockedCustomerLdapPublisher1.java 19902 2014-09-30
 *     14:32:24Z anatom $
 */
public class ThirdMockedCustomerLdapPublisher1 extends CustomerLdapPublisher1 {

      /** Param. */
  private boolean writeLogEntryToLDAPCalled;
  /** Param. */
  private final List<WriteLogEntryToLDAPParameters>
      writeLogEntryToLDAPParameters =
          new ArrayList<WriteLogEntryToLDAPParameters>();

  /** Param. */
  private final HashSet<String> storedDNs = new HashSet<String>();

  /** Param. */
  private long time;

  /**
   * @return time
   */
  public long getTime() {
    return time;
  }

  /**
   * @param atime time
   */
  public void setTime(final long atime) {
    this.time = atime;
  }

  @Override
  protected Date getCurrentTime() {
    return new Date(time);
  }

  // writeLogEntryToLDAP
  @Override
  protected void writeLogEntryToLDAP(
      final LDAPConnection lc, final LDAPEntry newEntry)
      throws PublisherException {
    this.writeLogEntryToLDAPCalled = true;
    this.writeLogEntryToLDAPParameters.add(
        new WriteLogEntryToLDAPParameters(lc, newEntry));
    if (!storedDNs.add(newEntry.getDN())) {
      final LDAPException ldapEx =
          new LDAPException(
              "Entry Exists",
              LDAPException.ENTRY_ALREADY_EXISTS,
              "entryAlreadyExists");
      final PublisherException pex =
          new PublisherException("Entry already exists");
      pex.initCause(ldapEx);
      throw pex;
    }
  }

  /**
   * @return bool
   */
  public boolean isWriteLogEntryToLDAPCalled() {
    return writeLogEntryToLDAPCalled;
  }

  /**
   * @return List
   */
  public List<WriteLogEntryToLDAPParameters>
      getWriteCertEntryToLDAPParameters() {
    return writeLogEntryToLDAPParameters;
  }

  /** Clear.
   */
  public void clearWriteCertEntryToLDAPParameters() {
    writeLogEntryToLDAPParameters.clear();
  }

  public static class WriteLogEntryToLDAPParameters {
        /** Param. */
    private final LDAPConnection lc;
    /** Param. */
    private final LDAPEntry newEntry;

    /**
     * @param anlc lc
     * @param anewEntry entry
     */
    public WriteLogEntryToLDAPParameters(
        final LDAPConnection anlc, final LDAPEntry anewEntry) {
      this.lc = anlc;
      this.newEntry = anewEntry;
    }

    /**
     * @return LC
     */
    public LDAPConnection getLc() {
      return lc;
    }

    /**
     * @return entry
     */
    public LDAPEntry getNewEntry() {
      return newEntry;
    }
  }
}
