/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.acme.response;

import java.io.Serializable;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;

/**
 * ACME Problem object JSON mapping.
 *
 * <p>https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-6.6
 *
 * <p>(The problem response object in ACME does not strictly follow
 * https://tools.ietf.org/html/rfc7807 "Problem Details for HTTP APIs".)
 *
 * @version $Id: AcmeProblemResponse.java 29587 2018-08-07 15:25:52Z mikekushner
 *     $
 */
public class AcmeProblemResponse implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Param. */
  @XmlElement(name = "type", required = true)
  private String type;

  /** Param. */
  @XmlElement(name = "title", required = false)
  private String title = null;

  /** Param. */
  @XmlElement(name = "status", required = false)
  private Integer status = null;

  /** Param. */
  @XmlElement(name = "detail", required = false)
  private String detail = null;
  /** For the userActionRequired error. */
  @XmlElement(name = "instance", required = false)
  private String instance = null;
  /**
   * For the badSignatureAlgorithm error we "MUST include an "algorithms" field
   * with an array of supported "alg" values".
   */
  @XmlElement(name = "algorithms", required = false)
  private List<String> algorithms;

  /** Param. */
  private String headerLink = null;
  /** Param. */
  private String headerLocation = null;

  /** null constructor. */
  public AcmeProblemResponse() { }

  /**
   * @param acmeProblem problem.
   */
  public AcmeProblemResponse(final AcmeProblem acmeProblem) {
    setType(acmeProblem.getType());
    setDetail(acmeProblem.getDetail());
  }

  /**
   * @param acmeProblem problem
   * @param thedetail detail
   */
  public AcmeProblemResponse(
      final AcmeProblem acmeProblem, final String thedetail) {
    setType(acmeProblem.getType());
    setDetail(thedetail);
  }

  /**
   * @return type
   */
  public String getType() {
    return type;
  }

  /**
   * @param atype type
   */
  public void setType(final String atype) {
    this.type = atype;
  }

  /**
   * @return title
   */
  public String getTitle() {
    return title;
  }

  /**
   * @param atitle title
   */
  public void setTitle(final String atitle) {
    this.title = atitle;
  }

  /**
   * @return Status
   */
  public Integer getStatus() {
    return status;
  }

  /**
   * @param astatus status
   */
  public void setStatus(final Integer astatus) {
    this.status = astatus;
  }

  /**
   * @return detail
   */
  public String getDetail() {
    return detail;
  }

  /**
   * @param thedetail detail
   */
  public void setDetail(final String thedetail) {
    this.detail = thedetail;
  }

  /**
   * @return instance
   */
  public String getInstance() {
    return instance;
  }

  /**
   * @param aninstance instance
   */
  public void setInstance(final String aninstance) {
    this.instance = aninstance;
  }

  /**
   * @return algos
   */
  public List<String> getAlgorithms() {
    return algorithms;
  }

  /**
   * @param thealgorithms algos
   */
  public void setAlgorithms(final List<String> thealgorithms) {
    this.algorithms = thealgorithms;
  }

  /**
   * @return link
   */
  public String getHeaderLink() {
    return headerLink;
  }

  /**
   * @param aheaderLink link
   */
  public void setHeaderLink(final String aheaderLink) {
    this.headerLink = aheaderLink;
  }

  /**
   * @return location
   */
  public String getHeaderLocation() {
    return headerLocation;
  }

  /**
   * @param aheaderLocation location
   */
  public void setHeaderLocation(final String aheaderLocation) {
    this.headerLocation = aheaderLocation;
  }

  /**
   * @param href link
   * @param rel relation
   */
  public void setHeaderLink(final String href, final String rel) {
    setHeaderLink("href=\"" + href + "\", rel=\"" + rel + "\"");
  }
}
