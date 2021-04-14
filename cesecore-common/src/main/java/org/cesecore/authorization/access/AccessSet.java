/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.authorization.access;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import org.cesecore.roles.AccessRulesHelper;

/**
 * Represents all access rules that a given AuthenticationToken is allowed to
 * access.
 *
 * @version $Id: AccessSet.java 25591 2017-03-23 13:13:02Z jeklund $
 * @deprecated since EJBCA 6.8.0
 */
@Deprecated
public final class AccessSet implements Serializable {
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(AccessSet.class);

  private static final long serialVersionUID = -6522714939328731306L;

  /** Max search depth. */
  private static final int MAX_DEPTH = 100;

  /**
   * Wildcard meaning: Access is granted to some items. Used only in calls to
   * isAuthorized to query whether we have access to any of the items (and in
   * AccessSet objects for faster access control checks).
   *
   * <p>Example: "/cryptotoken/use/*SOME", which would check if we have ccess to
   * use any cryptotoken.
   */
  public static final String WILDCARD_SOME = "*SOME";

  /**
   * Wildcard meaning: Access is granted recursively to all subresources (but
   * not the resource itself, for performance reasons). Used internally only,
   * never in calls to isAuthorized (AccessSets don't have anything like the
   * requireRecursive parameter).
   *
   * <p>Example: "/*RECURSIVE" together with "/", which would grant access to
   * everything
   *
   * @deprecated Since 6.8.0
   */
  @Deprecated public static final String WILDCARD_RECURSIVE = "*RECURSIVE";

  /** Pattern. */
  private static final Pattern ID_IN_RULENAME =
      Pattern.compile("^/(.+)/(-?[0-9]+)(/|$)");

  /**
   * Legacy storage of access rules in the AccessSet, used in EJBCA 6.6.0 and
   * 6.7.0.
   */
  @Deprecated private Collection<String> set;

  /** No-args constructor for deserialization only. */
  public AccessSet() { }

  /**
   * Creates an AccessSet with a legacy 6.6.0 access rule set, which can't
   * contain deny rules and works using the old access rule system.
   *
   * @param legacySet Rule set
   * @deprecated Since 6.8.0
   */
  @Deprecated
  public AccessSet(final Collection<String> legacySet) {
    this.set = new HashSet<>(legacySet);
  }

  /**
   * Creates an access set merged from two access sets.
   *
   * @param a Set a
   * @param b Set b
   */
  public AccessSet(final AccessSet a, final AccessSet b) {
    set = new HashSet<>(a.set.size() + b.set.size());
    set.addAll(a.set);
    set.addAll(b.set);
  }

  /**
   * Is access to the resource authorised?
   *
   * @param resources Resource
   * @return boolean
   */
  public boolean isAuthorized(final String... resources) {
    // Note that "*SOME" rules are added when the rules for the
    // AccessSet are built, and don't need to be handled here
    boolean result = true;
    NEXT_RESOURCE:
    for (final String resource : resources) {
      if (!result) {
          break;
         }
      checkResourceFormat(resource);

      // Check for exact rule
      if (set.contains(resource)) {
        continue NEXT_RESOURCE; // OK. Check next resource
      }

      // Check for recursive rules
      int depth = 0;
      String parentResource = resource;
      while (++depth < MAX_DEPTH) { // never split more than 100 times
        int slash = parentResource.lastIndexOf('/');
        if (slash == -1) {
          break;
        }
        parentResource = parentResource.substring(0, slash);
        logCheck(parentResource);
        if (set.contains(parentResource + "/" + WILDCARD_RECURSIVE)) {
          continue NEXT_RESOURCE; // OK. Check next resource
        }
      }
      logDepth(resource, depth);

      logAccess(resource);
      result = false;
    }
    return result; // all resources match
  }

  private void logDepth(final String resource, final int depth) {
      if (depth == MAX_DEPTH && LOG.isDebugEnabled()) {
          // Recursive rules are always accept rules, so it's safe to
          // ignore some of them and continue
          LOG.debug(
                  "Resource had more than 100 components, only the "
                    + "first 100 were checked for recursive accept access: "
                          + resource);
      }
  }

  private void logAccess(final String resource) {
      if (LOG.isTraceEnabled()) {
          LOG.trace(
                  "No access rule for "
                          + resource
                          + ". Denying access."
                          + " Number of allowed resources="
                          + set.size());
      }
  }

  private void logCheck(final String parentResource) {
      if (LOG.isTraceEnabled()) {
          LOG.trace(
                  "Checking for '"
                          + parentResource
                          + "/"
                          + WILDCARD_RECURSIVE
                          + "'");
      }
  }

  private void checkResourceFormat(
          final String resource) throws IllegalArgumentException {
      if (resource.charAt(0) != '/') {
          throw new IllegalArgumentException("Resource must start with /");
      } else if (resource.length() != 1
              && resource.charAt(resource.length() - 1) == '/') {
          throw new IllegalArgumentException("Resource should not end with /");
      }
  }

  /** Use in tests only. */
  public void dumpRules() {
    final List<String> resources = new ArrayList<>(set);
    Collections.sort(resources);
    LOG.debug("Legacy set");
    for (final String resource : resources) {
      LOG.debug("Resource: " + resource);
    }
  }

  @Override
  public String toString() {
    return Arrays.toString(set.toArray());
  }

  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (!(obj instanceof AccessSet)) {
      return false;
    }
    AccessSet other = (AccessSet) obj;
    if (set == null) {
      if (other.set != null) {
        return false;
      }
    } else if (!set.equals(other.set)) {
      return false;
    }
    return true;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((set == null) ? 0 : set.hashCode());
    return result;
  }

  /**
   * Converts from EJBCA 6.8.0+ access rules to the old version of AccessSet
   * introduced in EJBCA 6.6.0, for compatibility with old RA clients. The
   * result of the conversion is written to "set", which is a HashSet of every
   * single accepted resource enriched with "*SOME" but no "*RECURSIVE".
   *
   * <p>Before calling this method, the "accessMap" variable is expected to
   * contain the 6.8.0+ access rule structure.
   *
   * <p>Note: - The legacy set created via this method will not grant access to
   * a - configured rules that don't exist on the system. - ...and this means
   * that access to non-existing resources will not - be granted to old RA
   * clients.
   *
   * @param accessRules the EJBCA 6.8.0+ style access rules
   * @param allResources whole universe of resources that exists
   * @return an AccessSet of every single accepted resource enriched with
   *     "*SOME", but no "*RECURSIVE"
   */
  public static AccessSet fromAccessRules(
      final HashMap<String, Boolean> accessRules,
      final Set<String> allResources) {
    final Set<String> set = new HashSet<>();
    for (final String current : allResources) {
      // De-normalize if needed
      final String resource =
          current.length() > 1 && current.charAt(current.length() - 1) == '/'
              ? current.substring(0, current.length() - 1)
              : current;
      final boolean authorizedToResource =
          AccessRulesHelper.hasAccessToResource(accessRules, resource);
      if (authorizedToResource) {
        set.add(resource);
        // Check if we have an (integer) ID in the resource
        final Matcher matcher = ID_IN_RULENAME.matcher(resource);
        if (matcher.find()) {
          // Add "*SOME" resource
          final String someResource =
              matcher.replaceFirst("/$1/" + WILDCARD_SOME + "$3");
          set.add(someResource);
        }
      }
    }
    // Since expect the whole universe of rules to be provided,
    // there should be no need to add the WILDCARD_RECURSIVE rule
    return new AccessSet(set);
  }
}
