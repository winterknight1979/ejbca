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
package org.ejbca.ra;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.crl.CRLInfo;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.util.CertTools;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;

/**
 * Backing bean for Certificate and CRLs download page.
 *
 * @version $Id: RaCasPageBean.java 28756 2018-04-20 05:17:42Z bastianf $ TODO:
 *     Use CDI beans
 */
@SuppressWarnings("deprecation")
@ManagedBean
@ViewScoped
public class RaCasPageBean implements Serializable {

  /** Representation of a CA in a chain with links to CRL download locations. */
  public class CaAndCrl {
        /** Param. */
    private final String name;
    /** Param. */
    private final String subjectDn;
    /** Param. */
    private final int caId;
    /** Param. */
    private String crlLink;
    /** Param. */
    private String deltaCrlLink;
    /** Param. */
    private final int position;
    /** Param. */
    private final List<String> chainNames;
    /** Param. */
    private boolean x509 = false;

    CaAndCrl(
        final String aname,
        final String asubjectDn,
        final int acaId,
        final int aposition,
        final List<String> thechainNames) {
      this.name = aname;
      this.subjectDn = asubjectDn;
      this.caId = acaId;
      this.position = aposition;
      this.chainNames = thechainNames;
    }

    /**
     * @return Name
     */
    public String getName() {
      return name;
    }

    /**
     * @return DN
     */
    public String getSubjectDn() {
      return subjectDn;
    }

    /**
     * @return ID
     */
    public int getCaId() {
      return caId;
    }

    /**
     * @return link
     */
    public String getCrlLink() {
      return crlLink;
    }

    /**
     * @return link
     */
    public String getDeltaCrlLink() {
      return deltaCrlLink;
    }

    /**
     * @return pos
     */
    public int getPosition() {
      return position;
    }

    /**
     * @return bool
     */
    public boolean isX509() {
      return x509;
    }

    @Override
    public int hashCode() {
      return subjectDn.hashCode();
    }

    @Override
    public boolean equals(final Object obj) {
      return obj instanceof CaAndCrl
          && subjectDn.equals(((CaAndCrl) obj).subjectDn);
    }

    /**
     * @return the Subject DN string of the current certificate in unescaped RDN
     *     format
     */
    public final String getSubjectDnUnescapedRndValue() {
      if (StringUtils.isNotEmpty(subjectDn)) {
        return org.ietf.ldap.LDAPDN.unescapeRDN(subjectDn);
      } else {
        return subjectDn;
      }
    }
  }

  private static final long serialVersionUID = 1L;
  // private static final Logger log = Logger.getLogger(RaCasPageBean.class);
  /** Param. */
  private static final String RFC4387_DEFAULT_EJBCA_URL =
      WebConfiguration.getCrlStoreContextRoot() + "/search.cgi";
  /** Param. */
  private static final int NO_CAID_AVAILABLE = 0;

  /** Param. */
  @EJB private CrlStoreSessionLocal crlSession;
  /** Param. */
  @EJB private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

  /** Param. */
  @ManagedProperty(value = "#{raAuthenticationBean}")
  private RaAuthenticationBean raAuthenticationBean;

  /**
   * @param araAuthenticationBean bean
   */
  public void setRaAuthenticationBean(
      final RaAuthenticationBean araAuthenticationBean) {
    this.raAuthenticationBean = araAuthenticationBean;
  }


  /** Param. */
  @ManagedProperty(value = "#{raLocaleBean}")
  private RaLocaleBean raLocaleBean;

  /**
   * @param araLocaleBean bean
   */
  public void setRaLocaleBean(final RaLocaleBean araLocaleBean) {
    this.raLocaleBean = araLocaleBean;
  }

  /** Param. */
  private List<CaAndCrl> casAndCrlItems = null;
  /** Param. */
  private boolean atLeastOneCrlLinkPresent = false;

  /**
   * @return true if at least one of the CAs available via #getCasAndCrlItems()
   *     has CRLs present on this system.
   */
  public boolean isAtLeastOneCrlLinkPresent() {
    getCasAndCrlItems();
    return atLeastOneCrlLinkPresent && WebConfiguration.isCrlStoreEnabled();
  }

  /**
   * @return a list of all known authorized CAs with links to CRLs (if present)
   */
  public List<CaAndCrl> getCasAndCrlItems() {
    if (casAndCrlItems == null) {
      final List<CAInfo> caInfos =
          new ArrayList<>(
              raMasterApiProxyBean.getAuthorizedCas(
                  raAuthenticationBean.getAuthenticationToken()));
      // First build a mapping of all subjects and their short names
      final Map<String, String> caSubjectToNameMap = new HashMap<>();
      for (final CAInfo caInfo : caInfos) {
        caSubjectToNameMap.put(caInfo.getSubjectDN(), caInfo.getName());
      }
      // Convert all CA's chains into CA objects (use a Set to avoid duplicates)
      final Set<CaAndCrl> cas = new HashSet<>();
      for (final CAInfo caInfo : caInfos) {
        final List<Certificate> chain =
            new ArrayList<>(caInfo.getCertificateChain());
        Collections.reverse(chain);
        final List<String> chainNames = new ArrayList<>();
        final int caId = caInfo.getCAId();
        for (final Certificate caCertificate : chain) {
          final String subjectDn = CertTools.getSubjectDN(caCertificate);
          String name = caSubjectToNameMap.get(subjectDn);
          if (name == null) {
            name = subjectDn;
          }
          chainNames.add(name);
          final CaAndCrl caAndCrl =
              new CaAndCrl(
                  name,
                  subjectDn,
                  chainNames.size() == chain.size() ? caId : NO_CAID_AVAILABLE,
                  chainNames.size() - 1,
                  new ArrayList<>(chainNames));
          // Construct links to RFC4387 CRL Download Servlet
          if (caCertificate instanceof X509Certificate) {
            caAndCrl.x509 = true;
            final CRLInfo crlInfoFull =
                crlSession.getLastCRLInfo(subjectDn, false);
            if (crlInfoFull != null) {
              atLeastOneCrlLinkPresent = true;
              caAndCrl.crlLink =
                  RFC4387_DEFAULT_EJBCA_URL
                      + "?iHash="
                      + getSubjectPrincipalHashAsUnpaddedBase64(
                          (X509Certificate) caCertificate);
              final CRLInfo crlInfoDelta =
                  crlSession.getLastCRLInfo(subjectDn, true);
              if (crlInfoDelta != null) {
                caAndCrl.deltaCrlLink =
                    RFC4387_DEFAULT_EJBCA_URL
                        + "?iHash="
                        + getSubjectPrincipalHashAsUnpaddedBase64(
                            (X509Certificate) caCertificate)
                        + "&delta=";
              }
            }
          }
          // Add missing items and replace items when we know the CAId
          if (caAndCrl.getCaId() != NO_CAID_AVAILABLE) {
            cas.remove(caAndCrl);
          }
          if (!cas.contains(caAndCrl)) {
            cas.add(caAndCrl);
          }
        }
      }
      casAndCrlItems = new ArrayList<>(cas);
      // Sort by higher level CAs
      Collections.sort(
          casAndCrlItems,
          new Comparator<CaAndCrl>() {
            @Override
            public int compare(
                final CaAndCrl caAndCrl1, final CaAndCrl caAndCrl) {
              final int size1 = caAndCrl1.chainNames.size();
              final int size2 = caAndCrl.chainNames.size();
              // Avoid checking if chain length is the same
              for (int i = 0; i < Math.min(size1, size2); i++) {
                final String name1 = caAndCrl1.chainNames.get(i);
                final String name2 = caAndCrl.chainNames.get(i);
                final int compareTo = name1.compareTo(name2);
                if (compareTo != 0) {
                  return compareTo;
                }
              }
              return size1 - size2;
            }
          });
    }
    return casAndCrlItems;
  }

  /**
   * @param x509Certificate Cert
   * @return the issuer hash in base64 encoding without padding which is the way
   *     RFC4387 search function expects the iHash parameter.
   */
  private String getSubjectPrincipalHashAsUnpaddedBase64(
      final X509Certificate x509Certificate) {
    final int len = 27;
    final byte[] hashSubjectX500Principal =
        CertTools.generateSHA1Fingerprint(
            x509Certificate.getSubjectX500Principal().getEncoded());
    return new String(Base64.encode(hashSubjectX500Principal))
        .substring(0, len)
        .replaceAll("\\+", "%2B");
  }
}
