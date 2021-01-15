package org.ejbca.ui.web.admin.configuration;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import javax.ejb.EJBException;

/**
 * Class used to retrieve EJBCA image resources in JSF views
 *
 * <p>Implements a Map used for retrieving resources.
 *
 * @version $Id: EjbcaJSFImageResource.java 13640 2012-01-02 16:00:28Z
 *     mikekushner $
 * @see
 *     org.ejbca.ui.web.admin.configuration.EjbcaWebBean#getImagefileInfix(String)
 */
public class EjbcaJSFImageResource implements Map<String, String> {

    /** Bean. */
  private final EjbcaWebBean ejbcawebbean;

  /**
   * @param anejbcawebbean bean
   */
  public EjbcaJSFImageResource(final EjbcaWebBean anejbcawebbean) {
    this.ejbcawebbean = anejbcawebbean;
  }

  @Override
  public void clear() {
    throw new EJBException("Method clear not supported");
  }

  @Override
  public boolean containsKey(final Object arg0) {
    return ejbcawebbean.getImagefileInfix((String) arg0) != null;
  }

  @Override
  public boolean containsValue(final Object arg0) {
    throw new EJBException("Method containsValue not supported");
  }

  @Override
  public Set<Entry<String, String>> entrySet() {
    throw new EJBException("Method entrySet not supported");
  }

  @Override
  public String get(final Object arg0) {
    return ejbcawebbean.getImagefileInfix((String) arg0);
  }

  @Override
  public boolean isEmpty() {
    throw new EJBException("Method isEmpty not supported");
  }

  @Override
  public Set<String> keySet() {
    throw new EJBException("Method keySet not supported");
  }

  @Override
  public String put(final String arg0, final String arg1) {
    throw new EJBException("Method put not supported");
  }

  @Override
  public void putAll(final Map<? extends String, ? extends String> arg0) {
    throw new EJBException("Method putAll not supported");
  }

  @Override
  public String remove(final Object arg0) {
    throw new EJBException("Method remove not supported");
  }

  @Override
  public int size() {
    throw new EJBException("Method size not supported");
  }

  @Override
  public Collection<String> values() {
    throw new EJBException("Method values not supported");
  }
}
