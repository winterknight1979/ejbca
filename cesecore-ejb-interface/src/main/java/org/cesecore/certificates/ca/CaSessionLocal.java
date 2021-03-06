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
package org.cesecore.certificates.ca;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.ejb.Local;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * Local interface for CaSession.
 *
 * @version $Id: CaSessionLocal.java 29341 2018-06-26 07:19:21Z anatom $
 */
@Local
public interface CaSessionLocal extends CaSession {

  /**
   * Returns true if authorized to a CA without performing any logging
   * operations.
   *
   * @param admin the token to check against.
   * @param caid the ID of the CA in question
   * @return true if the token was authorized.
   */
  boolean authorizedToCANoLogging(
      AuthenticationToken admin, int caid);

  /**
   * Returns true if authorized to a CA.
   *
   * @param admin the token to check against.
   * @param caid the ID of the CA in question
   * @return true if the token was authorized.
   */
  boolean authorizedToCA(AuthenticationToken admin, int caid);

  /**
   * @return a list of all CAData objects, or an empty list if none were found.
   */
  List<CAData> findAll();

  /**
   * @param cAId CA
   * @return the found entity instance or null if the entity does not exist
   */
  CAData findById(Integer cAId);

  /**
   * @param cAId CA
   * @throws CADoesntExistsException if the entity does not exist
   * @return the found entity instance
   */
  CAData findByIdOrThrow(Integer cAId) throws CADoesntExistsException;

  /**
   * @param name Name
   * @throws javax.persistence.NonUniqueResultException if more than one entity
   *     with the name exists
   * @return the found entity instance or null if the entity does not exist
   */
  CAData findByName(String name);

  /**
   * @param name Name
   * @throws CADoesntExistsException if the entity does not exist
   * @throws javax.persistence.NonUniqueResultException if more than one entity
   *     with the name exists
   * @return the found entity instance
   */
  CAData findByNameOrThrow(String name) throws CADoesntExistsException;

  /**
   * Makes sure that no CAs are cached to ensure that we read from database next
   * time we try to access it.
   */
  void flushCACache();

  /**
   * Get the CA object performing the regular authorization check. Checks if the
   * CA has expired or the certificate isn't valid yet and in that case sets the
   * correct CA status. NOTE: This method will return a shared CA object from a
   * cache. Not suitable for reading a CA object that you plan to edit. Use this
   * when you need to use the CA, since it's faster. User getCAForEdit if you
   * want to edit the CA object and does not want your changes to be overwritten
   * by another thread.
   *
   * @see #getCAForEdit(AuthenticationToken, String)
   * @param admin AuthenticationToken of admin
   * @param caid identifies the CA
   *     (CertTools.stringToBCDNString(StringTools.strip(caSubjectDN)).hashCode())
   * @return the CA object, or null if it doesn't exist.
   * @throws AuthorizationDeniedException if not authorized to get CA
   */
  CA getCA(AuthenticationToken admin, int caid)
      throws AuthorizationDeniedException;

  /**
   * Get the CA object performing the regular authorization check. Checks if the
   * CA has expired or the certificate isn't valid yet and in that case sets the
   * correct CA status. NOTE: This method will return a shared CA object from a
   * cache. Not suitable for reading a CA object that you plan to edit. Use this
   * when you need to use the CA, since it's faster. User getCAForEdit if you
   * want to edit the CA object and does not want your changes to be overwritten
   * by another thread.
   *
   * @see #getCAForEdit(AuthenticationToken, String)
   * @param admin AuthenticationToken of admin
   * @param name name of the CA that we are searching for
   * @return CA value object, or null if it doesn't exist.
   * @throws AuthorizationDeniedException if not authorized to get CA
   */
  CA getCA(AuthenticationToken admin, String name)
      throws AuthorizationDeniedException;

  /**
   * Get the CA object performing the regular authorization check. Checks if the
   * CA has expired or the certificate isn't valid yet and in that case sets the
   * correct CA status. NOTE: This method will return a new CA object from the
   * database. Not suitable for reading a CA object that you plan to simply use.
   * Use this when you need to edit the CA object, since it's slower. User getCA
   * if you want to simply use the CA object and does not need to make edits.
   *
   * @see #getCA(AuthenticationToken, String)
   * @param admin AuthenticationToken of admin
   * @param caid identifies the CA
   *     (CertTools.stringToBCDNString(StringTools.strip(caSubjectDN)).hashCode())
   * @return CA value object, or null if it doesn't exist.
   * @throws AuthorizationDeniedException if not authorized to get CA
   */
  CA getCAForEdit(AuthenticationToken admin, int caid)
      throws AuthorizationDeniedException;

  /**
   * Get the CA object performing the regular authorization check. Checks if the
   * CA has expired or the certificate isn't valid yet and in that case sets the
   * correct CA status. NOTE: This method will return a new CA object from the
   * database. Not suitable for reading a CA object that you plan to simply use.
   * Use this when you need to edit the CA object, since it's slower. User getCA
   * if you want to simply use the CA object and does not need to make edits.
   *
   * @see #getCA(AuthenticationToken, String)
   * @param admin AuthenticationToken of admin
   * @param name name of the CA that we are searching for
   * @return CA value object, or null if it doesn't exist.
   * @throws AuthorizationDeniedException if not authorized to get CA
   */
  CA getCAForEdit(AuthenticationToken admin, String name)
      throws AuthorizationDeniedException;

  /**
   * Changes a CA in the database. Can change mostly everything except caid,
   * caname and subject DN. When editing a CA the CA token will usually be taken
   * off line. So you need to activate the CA token after editing, if
   * auto-activation of the CA token is not enabled.
   *
   * @param admin AuthenticationToken of admin
   * @param ca the CA to edit
   * @param auditlog if audit logging of the edit should be done or not, not
   *     needed if called from other internal methods that already does audit
   *     logging.
   * @throws CADoesntExistsException If CA not found
   * @throws AuthorizationDeniedException If access denied
   */
  void editCA(AuthenticationToken admin, CA ca, boolean auditlog)
      throws CADoesntExistsException, AuthorizationDeniedException;

  /**
   * Verify that a CA exists.
   *
   * @param caid is the id of the CA
   *     (CertTools.stringToBCDNString(StringTools.strip(caSubjectDN))
   * @throws CADoesntExistsException if the CA is not found
   */
  void verifyExistenceOfCA(int caid) throws CADoesntExistsException;

  /**
   * Returns a HashMap containing mappings of caid (Integer) to CA name (String)
   * of all CAs in the system.
   *
   * @return HashMap with Integer-&gt;String mappings
   */
  HashMap<Integer, String> getCAIdToNameMap();

  /**
   * Returns a HashMap containing mappings of caid (Integer) to CA name (String)
   * of all active and uninitialized CAs in the system that the admin is
   * authorized to.
   *
   * @param authenticationToken Auth token
   * @return HashMap with Integer-&gt;String mappings
   */
  Map<Integer, String> getActiveCAIdToNameMap(
      AuthenticationToken authenticationToken);

  /**
   * Internal (local only) method for getting CAInfo, to avoid access control
   * logging for internal operations. Tries to find the CA even if the CAId is
   * wrong due to CA certificate DN not being the same as CA DN.
   *
   * <p>Note! No authorization checks performed in this internal method
   *
   * @param caid numerical id of CA
   *     (CertTools.stringToBCDNString(StringTools.strip(caSubjectDN)).hashCode())
   *     that we search for, or -1 if a name is to be used instead
   * @param name human readable name of CA, used instead of caid if caid == -1,
   *     can be null if caid != -1
   * @param fromCache if we should use the CA cache or return a new, decoupled,
   *     instance from the database, to be used when you need a completely
   *     distinct object, for edit, and not a shared cached instance.
   * @return CA value object, or null if it doesn't exist.
   */
  CAInfo getCAInfoInternal(
      int caid, String name, boolean fromCache);

  /**
   * Internal (local only) method for getting CAInfo, to avoid access control
   * logging for internal operations.
   *
   * <p>Note! No authorization checks performed in this internal method
   *
   * @param caid numerical id of CA
   *     (CertTools.stringToBCDNString(StringTools.strip(caSubjectDN)).hashCode())
   *     that we search for
   * @return CA value object, or null if it doesn't exist.
   */
  CAInfo getCAInfoInternal(int caid);

  /**
   * Internal (local only) method to get the CA object without logging the
   * authorization check. (the auth check is performed though)
   *
   * <p>NOTE: This method will return a shared CA object from a cache. Not
   * suitable for reading a CA object that you plan to edit. Use this when you
   * need to use the CA, since it's faster. User getCAForEdit if you want to
   * edit the CA object and does not want your changes to be overwritten by
   * another thread.
   *
   * @see #getCAForEdit(AuthenticationToken, String)
   * @param admin AuthenticationToken of admin
   * @param caid identifies the CA
   *     (CertTools.stringToBCDNString(StringTools.strip(caSubjectDN)).hashCode())
   * @return the CA object, or null if it doesn't exist.
   * @throws AuthorizationDeniedException if not authorized to get CA
   */
  CA getCANoLog(AuthenticationToken admin, int caid)
      throws AuthorizationDeniedException;

  /**
   * Local access CRUD method for persisting the CA object to the database and
   * removes any old object with this CA id from the cache.
   *
   * @param ca CA
   * @return the CA Id
   */
  int mergeCa(CA ca);

  /**
   * Checks if at least one CA references a key validator.
   *
   * @param keyValidatorId Validator
   * @return true if there are no references.
   * @throws AuthorizationDeniedException if not authorized.
   */
  boolean existsKeyValidatorInCAs(int keyValidatorId)
      throws AuthorizationDeniedException;
}
