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

package org.ejbca.config;

import java.io.Serializable;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import org.cesecore.configuration.ConfigurationBase;

/**
 * Handles configuration of protocols supporting enable / disable.
 *
 * @version $Id: AvailableProtocolsConfiguration.java 29241 2018-06-15 15:08:02Z
 *     henriks $
 */
public class AvailableProtocolsConfiguration extends ConfigurationBase
    implements Serializable {
  private static final long serialVersionUID = 1L;

  /**ID. */
  public static final String CONFIGURATION_ID = "AVAILABLE_PROTOCOLS";

  /** Protocols currently supporting enable/disable configuration by EJBCA. */
  public enum AvailableProtocols {
    // If you add a protocol > 6.11.0 it should be disabled by default
    /** ACME. */
    ACME("ACME", "/ejbca/acme"),
    /** CERT. */
    CERT_STORE("Certstore", "/certificates"),
    /** CMP. */
    CMP("CMP", "/ejbca/publicweb/cmp"),
    /** CRLs. */
    CRL_STORE("CRLstore", "/crls"),
    /** EST. */
    EST("EST", "/.well-known/est"),
    /** OCSP. */
    OCSP("OCSP", "/ejbca/publicweb/status/ocsp"),
    /** Web. */
    PUBLIC_WEB("Public Web", "/ejbca"),
    /** SCEP. */
    SCEP("SCEP", "/ejbca/publicweb/apply/scep"),
    /** RA. */
    RA_WEB("RA Web", "/ejbca/ra"),
    /** REST. */
    REST("REST Certificate Management", "/ejbca/ejbca-rest-api"),
    /** Dist. */
    WEB_DIST("Webdist", "/ejbca/publicweb/webdist"),
    /** WS. */
    WS("Web Service", "/ejbca/ejbcaws");

      /** Name. */
    private final String name;
    /** URL. */
    private final String url;
    /** Map. */
    private static final Map<String, String> REVERSE_LOOKUP_MAP =
            new HashMap<>();

    static {
      for (final AvailableProtocols protocol : AvailableProtocols.values()) {
        REVERSE_LOOKUP_MAP.put(protocol.getName(), protocol.getUrl());
      }
    }

    /**
     * Creates a new instance of an available protocol enum.
     *
     * @param aName the name of the enum, same as the "serviceName" from web.xml
     * @param aUrl the URL to the servlet
     */
    AvailableProtocols(final String aName, final String aUrl) {
      this.name = aName;
      this.url = aUrl;
    }

    /** @return user friendly name of protocol */
    public String getName() {
      return name;
    }

    /**
     * @return URL
     */
    public String getUrl() {
      return url;
    }

    /**
     * @param name Name
     * @return Path
     */
    public static String getContextPathByName(final String name) {
      return REVERSE_LOOKUP_MAP.get(name);
    }
  };

  /** Initializes the configuration. */
  public AvailableProtocolsConfiguration() {
    super();
  }

  /**
   * Checks whether protocol is enabled / disabled locally.
   *
   * @param protocol to check status of @see {@link AvailableProtocols}
   * @return true if protocol is enabled, false otherwise
   */
  public boolean getProtocolStatus(final String protocol) {
    Boolean ret = (Boolean) data.get(protocol);
    // All protocols added > 6.11.0 should be disabled by default
    if (ret == null
        && (protocol.equals(AvailableProtocols.ACME.getName())
            || protocol.equals(AvailableProtocols.EST.getName())
            || protocol.equals(AvailableProtocols.REST.getName()))) {
      setProtocolStatus(protocol, false);
      return false;
    }
    return ret == null ? true : ret;
  }

  /**
   * @param protocol Protocol
   * @param status Status
   */
  public void setProtocolStatus(final String protocol, final boolean status) {
    data.put(protocol, status);
  }

  /**
   * @return map containing the current status of all configurable protocols.
   */
  public LinkedHashMap<String, Boolean> getAllProtocolsAndStatus() {
    LinkedHashMap<String, Boolean> protocolStatusMap = new LinkedHashMap<>();
    for (AvailableProtocols protocol : AvailableProtocols.values()) {
      protocolStatusMap.put(
          protocol.getName(), getProtocolStatus(protocol.getName()));
    }
    return protocolStatusMap;
  }

  @Override
  public String getConfigurationId() {
    return CONFIGURATION_ID;
  }

  @Override
  public void upgrade() {
    if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
      data.put(VERSION, Float.valueOf(LATEST_VERSION));
    }
  }
}
