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
package org.ejbca.ra.jsfext;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.ejb.EJBException;
import javax.el.ELException;
import javax.faces.FacesException;
import javax.faces.application.ViewExpiredException;
import javax.faces.context.ExceptionHandler;
import javax.faces.context.ExceptionHandlerFactory;
import javax.faces.context.ExceptionHandlerWrapper;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.event.ExceptionQueuedEvent;
import org.apache.log4j.Logger;

/**
 * Custom ExceptionHandlerFactory to be able to process and present Exceptions
 * in an orderly fashion.
 *
 * <p>Enabled in faces-config.xml with &lt;factory&gt;
 * &lt;exception-handler-factory&gt;org.ejbca.ra.jsfext.RaExceptionHandlerFactory&lt;/exception-handler-factory&gt;
 * &lt;/factory&gt;
 *
 * @version $Id: RaExceptionHandlerFactory.java 34547 2020-02-28 13:52:37Z
 *     samuellb $
 */
public class RaExceptionHandlerFactory extends ExceptionHandlerFactory {

      /** Param. */
  private static final Logger LOG = Logger.getLogger(RaExceptionHandler.class);
  /** Param. */
  public static final String REQUESTMAP_KEY = "org.ejbca.ra.jsfext.throwables";
  /** Param. */
  private static final String ERROR_PAGE = "/error.xhtml";

  /** Param. */
  private final ExceptionHandlerFactory parentExceptionHandlerFactory;

  /**
   * @param aparent parent
   */
  public RaExceptionHandlerFactory(final ExceptionHandlerFactory aparent) {
      ExceptionHandlerFactory parent = aparent;
    while (parent instanceof RaExceptionHandlerFactory) {
      LOG.warn(
          "Attempted to wrap a RaExceptionHandlerFactory in a"
              + " RaExceptionHandlerFactory");
      if (parent == this) {
        throw new IllegalStateException(
            "Circular reference in exception handler");
      }
      parent = parent.getWrapped();
    }
    this.parentExceptionHandlerFactory = parent;
  }

  @Override
  public ExceptionHandler getExceptionHandler() {
    return new RaExceptionHandler(
        parentExceptionHandlerFactory.getExceptionHandler());
  }

  /** Our custom ExceptionHandler implementation. */
  private class RaExceptionHandler extends ExceptionHandlerWrapper {
      /** Handler. */
    private final ExceptionHandler wrappedExceptionHandler;

    /**
     * @param awrappedExceptionHandler handler
     */
    RaExceptionHandler(final ExceptionHandler awrappedExceptionHandler) {
      this.wrappedExceptionHandler = awrappedExceptionHandler;
    }

    @Override
    public ExceptionHandler getWrapped() {
      return wrappedExceptionHandler;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void handle() throws FacesException {
      final List<Throwable> throwables = new ArrayList<>();
      for (final Iterator<ExceptionQueuedEvent> iterator =
              super.getUnhandledExceptionQueuedEvents().iterator();
          iterator.hasNext();) {
        Throwable throwable = iterator.next().getContext().getException();
        // Filter away JEE Exception wrappers
        while ((throwable instanceof FacesException
                || throwable instanceof EJBException
                || throwable instanceof ELException)
            && throwable.getCause() != null) {
          throwable = throwable.getCause();
        }
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Adding throwable "
                  + throwable.getClass().getSimpleName()
                  + ": "
                  + throwable.getMessage());
        }
        throwables.add(throwable);
        iterator.remove();
      }
      if (!throwables.isEmpty()) {
        final FacesContext facesContext = FacesContext.getCurrentInstance();
        final ExternalContext externalContext =
            facesContext.getExternalContext();
        if (externalContext.getRequestMap().get(REQUESTMAP_KEY) == null) {
          externalContext.getRequestMap().put(REQUESTMAP_KEY, throwables);
          try {
            externalContext.dispatch(ERROR_PAGE);
          } catch (final IOException e) {
            LOG.error(
                "Unable to dispatch client to unknown error page '"
                    + ERROR_PAGE
                    + "'.",
                e);
          }
          facesContext.responseComplete();
        } else {
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Additional ExceptionHandler invocation during same round"
                    + " trip...");
          }
          boolean hasViewExpiredException = false;
          for (final Throwable throwable : throwables) {
            if (throwable instanceof ViewExpiredException) {
              hasViewExpiredException = true;
              break;
            }
          }
          for (final Throwable throwable
              : (List<Throwable>)
                  externalContext.getRequestMap().get(REQUESTMAP_KEY)) {
            if (hasViewExpiredException
                && throwable instanceof ViewExpiredException) {
              if (LOG.isDebugEnabled()) {
                LOG.debug("Skipping add of another ViewExpiredException.");
              }
            } else {
              throwables.add(throwable);
            }
          }
          externalContext.getRequestMap().put(REQUESTMAP_KEY, throwables);
        }
      }
      getWrapped().handle();
    }
  }
}
