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

import java.io.Serializable;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.common.exception.ReferencesToItemExistException;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherDoesntExistsException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;

/**
 * A class handling the hardtoken profile data in the webinterface.
 *
 * @deprecated since 6.12.0. Use PublisherSession directly instead
 * @version $Id: PublisherDataHandler.java 30470 2018-11-12 11:02:11Z samuellb $
 */
@Deprecated
public class PublisherDataHandler implements Serializable {

  private static final long serialVersionUID = -5646053740072121787L;

  /** POarem. */
  private final PublisherSessionLocal publishersession;
  /** POarem. */
  private final AuthenticationToken administrator;

  /**
   * Creates a new instance of PublisherDataHandler.
   *
   * @param anadministrator Admin
   * @param apublishersession Session
   */
  public PublisherDataHandler(
      final AuthenticationToken anadministrator,
      final PublisherSessionLocal apublishersession) {
    this.publishersession = apublishersession;
    this.administrator = anadministrator;
  }

  /**
   * Method to add a publisher. Throws PublisherExitsException if profile
   * already exists
   *
   * @param name Name
   * @param publisher Pub
   * @throws PublisherExistsException Fail
   * @throws AuthorizationDeniedException Fail
   */
  public void addPublisher(final String name, final BasePublisher publisher)
      throws PublisherExistsException, AuthorizationDeniedException {
    publishersession.addPublisher(administrator, name, publisher);
  }

  /**
   * Method to change a publisher.
   *
   * @param name Name
   * @param publisher Pub
   * @throws AuthorizationDeniedException fail
   */
  public void changePublisher(final String name, final BasePublisher publisher)
      throws AuthorizationDeniedException {
    publishersession.changePublisher(administrator, name, publisher);
  }

  /**
   * Removes a publisher.
   *
   * @param name Name
   * @throws AuthorizationDeniedException if not authorized
   * @throws ReferencesToItemExistException if references exist.
   */
  public void removePublisher(final String name)
      throws ReferencesToItemExistException, AuthorizationDeniedException {
    publishersession.removePublisher(administrator, name);
  }

  /**
   * Metod to rename a publisher.
   *
   * @param oldname Name
   * @param newname Name
   * @throws PublisherExistsException fail
   * @throws AuthorizationDeniedException fail
   */
  public void renamePublisher(final String oldname, final String newname)
      throws PublisherExistsException, AuthorizationDeniedException {
    publishersession.renamePublisher(administrator, oldname, newname);
  }
  /**
   * Metod to clone a publisher.
   *
   * @param originalname Name
   * @param newname Name
   * @throws PublisherExistsException fail
   * @throws AuthorizationDeniedException fail
 * @throws PublisherDoesntExistsException  fail
   */
  public void clonePublisher(final String originalname, final String newname)
      throws AuthorizationDeniedException, PublisherDoesntExistsException,
          PublisherExistsException {
    publishersession.clonePublisher(administrator, originalname, newname);
  }

  /**
   * @param name Name
   * @throws PublisherConnectionException Fail
   */
  public void testConnection(final String name)
      throws PublisherConnectionException {
    publishersession.testConnection(publishersession.getPublisherId(name));
  }

  /**
   * @param name Name
   * @return Pub
   */
  public BasePublisher getPublisher(final String name) {
    return publishersession.getPublisher(name);
  }

  /**
   * @param name Name
   * @return ID
   */
  public int getPublisherId(final String name) {
    return publishersession.getPublisherId(name);
  }
}
