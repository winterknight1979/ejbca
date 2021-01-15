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

package org.ejbca.ui.web.admin.rainterface;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * A class representing a set of users.
 *
 * @version $Id: UsersView.java 28844 2018-05-04 08:31:02Z samuellb $
 */
public class UsersView implements Serializable {

  private static final long serialVersionUID = -7382135359016557800L;
  /** Creates a new instance of UsersView. */
  public UsersView() {
    users = new ArrayList<>();
    sortby = new SortBy();
  }

  /**
   * @param importuser User
   * @param caidtonamemap Map
   */
  public UsersView(
      final EndEntityInformation importuser,
      final HashMap<Integer, String> caidtonamemap) {
    users = new ArrayList<>();
    sortby = new SortBy();
    users.add(new UserView(importuser, caidtonamemap));

    Collections.sort(users);
  }

  /**
   * @param importusers Users
   * @param caidtonamemap Map
   */
  public UsersView(
      final Collection<EndEntityInformation> importusers,
      final HashMap<Integer, String> caidtonamemap) {
    users = new ArrayList<>();
    sortby = new SortBy();

    setUsers(importusers, caidtonamemap);
  }
  // Public methods.

  /**
   * @param asortby Sort
   * @param sortorder Order
   */
  public void sortBy(final int asortby, final int sortorder) {
    this.sortby.setSortBy(asortby);
    this.sortby.setSortOrder(sortorder);

    Collections.sort(users);
  }

  /**
   * @param oindex Index
   * @param size Size
   * @return Users
   */
  public UserView[] getUsers(final int oindex, final int size) {
    int endindex;
    UserView[] returnval;
    int index = oindex;
    if (index > users.size()) {
      index = users.size() - 1;
    }
    if (index < 0) {
      index = 0;
    }

    // The below is used in order to return all the values in one page
    // JasperReports has its own multiple page setings (right now it will print
    // all pages inside a single web page, one after the other)
    // i think this functions were first used in very specific places, where the
    // user asks directly for a single page at once depending on the number of
    // results in one page.  If this number is -1 then all results will be on
    // one single page
    if (size == -1) {
      endindex = users.size();
    } else {
      endindex = index + size;
      if (endindex > users.size()) {
        endindex = users.size();
      }
    }

    returnval = new UserView[endindex - index];

    int end = endindex - index;
    for (int i = 0; i < end; i++) {
      returnval[i] = users.get(index + i);
    }

    return returnval;
  }

  /**
   * @param thwusers Users
   */
  public void setUsers(final UserView[] thwusers) {
    this.users.clear();
    if (thwusers != null && thwusers.length > 0) {
      for (int i = 0; i < thwusers.length; i++) {
        thwusers[i].setSortBy(this.sortby);
        this.users.add(thwusers[i]);
      }
    }
    Collections.sort(this.users);
  }

  /**
   * @param theusers Users
   * @param caidtonamemap Map
   */
  public void setUsers(
      final EndEntityInformation[] theusers,
      final Map<Integer, String> caidtonamemap) {
    UserView user;
    this.users.clear();
    if (theusers != null && theusers.length > 0) {
      for (int i = 0; i < theusers.length; i++) {
        user = new UserView(theusers[i], caidtonamemap);
        user.setSortBy(this.sortby);
        this.users.add(user);
      }
      Collections.sort(this.users);
    }
  }

  /**
   * @param importusers Users
   * @param caidtonamemap Map
   */
  public void setUsers(
      final Collection<EndEntityInformation> importusers,
      final Map<Integer, String> caidtonamemap) {

    UserView user;
    Iterator<EndEntityInformation> i;
    this.users.clear();
    if (importusers != null && importusers.size() > 0) {
      i = importusers.iterator();
      while (i.hasNext()) {
        EndEntityInformation nextuser = i.next();
        user = new UserView(nextuser, caidtonamemap);
        user.setSortBy(this.sortby);
        users.add(user);
      }
      Collections.sort(users);
    }
  }

  /**
   * @param user User
   */
  public void addUser(final UserView user) {
    user.setSortBy(this.sortby);
    users.add(user);
  }

  /**
   * @return Size
   */
  public int size() {
    return users.size();
  }

  /** Clear. */
  public void clear() {
    this.users.clear();
  }
  // Private fields
  /** Param. */
  private final List<UserView> users;

  /** Param. */
  private final SortBy sortby;
}
