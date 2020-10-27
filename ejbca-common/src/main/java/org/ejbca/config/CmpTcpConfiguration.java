package org.ejbca.config;

public final class CmpTcpConfiguration {

    private CmpTcpConfiguration() { }

    /**
     * @return Port
     */
  public static int getTCPPortNumber() {
    return Integer.valueOf(
        EjbcaConfigurationHolder.getString("cmp.tcp.portno"));
  }

  /**
   * @return Log
   */
  public static String getTCPLogDir() {
    return EjbcaConfigurationHolder.getString("cmp.tcp.logdir");
  }

  /**
   * @return Config
   */
  public static String getTCPConfigFile() {
    return EjbcaConfigurationHolder.getString("cmp.tcp.conffile");
  }

  /**
   * @return Address
   */
  public static String getTCPBindAdress() {
    return EjbcaConfigurationHolder.getString("cmp.tcp.bindadress");
  }
}
