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
package org.cesecore.audit;

import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.cesecore.audit.audit.AuditExporter;
import org.cesecore.audit.impl.AuditExporterDummy;
import org.cesecore.config.ConfigurationHolderUtil;
import org.cesecore.util.ValidityDateUtil;

/**
 * Parses configuration related to the log devices.
 *
 * <p>Custom properties for each device is reformatted. E.g.
 * "securityeventsaudit.deviceproperty.1.key1.key2=value" is available to the
 * log device implementation 1 as "key1.key2=value"
 *
 * @version $Id: AuditDevicesConfig.java 17625 2013-09-20 07:12:06Z netmackan $
 */
public final class AuditDevicesConfig {

    private AuditDevicesConfig() { }
    /** Logger. */
  private static final Logger LOG = Logger.getLogger(AuditDevicesConfig.class);
  /** Thread lock. */
  private static final ReentrantLock LOCK = new ReentrantLock(false);
  /** Loggers. */
  private static Map<String, AuditLogDevice> loggers = null;
  /** Exporters. */
  private static final Map<String, Class<? extends AuditExporter>> EXPORTERS =
      new HashMap<String, Class<? extends AuditExporter>>();
  /** Props. */
  private static final Map<String, Properties> DEVICE_PROPERTIES =
      new HashMap<String, Properties>();

  private static Map<String, AuditLogDevice> getLoggers() {
    setup();
    return loggers;
  }

  @SuppressWarnings("unchecked")
  private static void setup() {
    try {
      LOCK.lock();
      if (loggers == null) {
        loggers = new HashMap<String, AuditLogDevice>();
        final Configuration conf = ConfigurationHolderUtil.instance();
        final String deviceClassRoot = "securityeventsaudit.implementation.";
        final String exporterClassRoot = "securityeventsaudit.exporter.";
        // Extract custom properties configured for any device, to avoid lookup
        // for each device later on..
        // Default devices should not require configuring of 'deviceproperty' in
        // defaultvalues.properties,
        // since the below Iterator does not read from default values.
        final String deviceProperty =
            "securityeventsaudit\\.deviceproperty\\.(\\d+)\\.(.+)";
        final Map<Integer, Properties> allDeviceProperties =
            new HashMap<Integer, Properties>();
        final Iterator<String> iterator = conf.getKeys();
        while (iterator.hasNext()) {
          final String currentKey = iterator.next();
          Pattern pattern = Pattern.compile(deviceProperty);
          Matcher matcher = pattern.matcher(currentKey);
          if (matcher.matches()) {
            final Integer deviceConfId = Integer.parseInt(matcher.group(1));
            Properties thedeviceProperties =
                    allDeviceProperties.get(deviceConfId);
            if (thedeviceProperties == null) {
              thedeviceProperties = new Properties();
            }
            final String devicePropertyName = matcher.group(2);
            final String devicePropertyValue = conf.getString(currentKey);
            if (LOG.isDebugEnabled()) {
              LOG.debug(
                  "deviceConfId="
                      + deviceConfId.toString()
                      + " "
                      + devicePropertyName
                      + "="
                      + devicePropertyValue);
            }
            thedeviceProperties.put(devicePropertyName, devicePropertyValue);
            allDeviceProperties.put(deviceConfId, thedeviceProperties);
          }
        }
        for (int i = 0; i < 255; i++) {
          if (!checkNoDuplicateProperties(deviceClassRoot + i)) {
            continue;
          }
          final String deviceClass =
              ConfigurationHolderUtil.getString(deviceClassRoot + i);
          if ((deviceClass != null)
              && (!"null".equalsIgnoreCase(deviceClass))) {
            if (LOG.isDebugEnabled()) {
              LOG.debug(
                  "Trying to register audit device using implementation: "
                      + deviceClass);
            }
            try {
              // Instantiate device
              final Class<AuditLogDevice> implClass =
                  (Class<AuditLogDevice>) Class.forName(deviceClass);
              final AuditLogDevice auditLogDevice =
                  implClass.getConstructor().newInstance();
              final String name = implClass.getSimpleName();
              loggers.put(name, auditLogDevice);
              LOG.info(
                  "Registered audit device using implementation: "
                      + deviceClass);
              // Store custom properties for this device, so they are searchable
              // by name
              if (!allDeviceProperties.containsKey(Integer.valueOf(i))) {
                allDeviceProperties.put(Integer.valueOf(i), new Properties());
              }
              DEVICE_PROPERTIES.put(
                  name, allDeviceProperties.get(Integer.valueOf(i)));
              // Setup an exporter for this device
              final String exporterClassName =
                  ConfigurationHolderUtil.getString(exporterClassRoot + i);
              Class<? extends AuditExporter> exporterClass =
                  AuditExporterDummy.class;
              if (exporterClassName != null) {
                try {
                  exporterClass =
                      (Class<? extends AuditExporter>)
                          Class.forName(exporterClassName);
                } catch (Exception e) {
                  // ClassCastException, ClassNotFoundException
                  LOG.error(
                      "Could not configure exporter for audit device "
                          + name
                          + " using implementation: "
                          + exporterClass,
                      e);
                }
              }
              LOG.info(
                  "Configured exporter "
                      + exporterClass.getSimpleName()
                      + " for device "
                      + name);
              EXPORTERS.put(name, exporterClass);
            } catch (Exception e) {
              // ClassCastException, ClassNotFoundException,
              // InstantiationException, IllegalAccessException
              LOG.error(
                  "Could not creating audit device using implementation: "
                      + deviceClass,
                  e);
            }
          }
        }
        if (loggers.isEmpty()) {
          LOG.warn("No security event audit devices has been configured.");
        }
      }
    } finally {
      LOCK.unlock();
    }
  }

  /**
   * Checks that there are no duplicate properties in the configuration.
   *
   * @param name Propertiy name
   * @return boolean
   */
  private static boolean checkNoDuplicateProperties(final String name) {
   final String[] arr = ConfigurationHolderUtil.instance().getStringArray(name);
    if (arr != null && arr.length > 1) {
      LOG.error(
          "Duplicate property definitions of \""
              + name
              + "\". All defintions ("
              + arr.length
              + " occurrences) of this property will be ignored.");
      return false;
    }
    return true;
  }

  /**
   * @return the ids of all devices that support querying as a serilizable
   *     (Hash)Set.
   */
  public static Set<String> getQuerySupportingDeviceIds() {
    final Set<String> set = new HashSet<String>();
    for (final String id : getLoggers().keySet()) {
      if (loggers.get(id).isSupportingQueries()) {
        set.add(id);
      }
    }
    return set;
  }

  /** @return the ids of all devices as a serilizable (Hash)Set. */
  public static Set<String> getAllDeviceIds() {
    return new HashSet<String>(getLoggers().keySet());
  }

  /**
   * @param ejbs Beans
   * @param id ID
   * @return Device
   */
  public static AuditLogDevice getDevice(
      final Map<Class<?>, ?> ejbs, final String id) {
    final AuditLogDevice auditLogDevice = getLoggers().get(id);
    if (auditLogDevice != null) {
      auditLogDevice.setEjbs(ejbs);
    }
    return auditLogDevice;
  }

  /**
   * @param id ID
   * @return Exporter class
   */
  public static Class<? extends AuditExporter> getExporter(final String id) {
    setup();
    return EXPORTERS.get(id);
  }

  /**
   * @param id ID
   * @return Props
   */
  public static Properties getProperties(final String id) {
    setup();
    return DEVICE_PROPERTIES.get(id);
  }

  /** Format. */
  private static final String EXPORTFILE_DATE_FORMAT = "yyyy-MM-dd-HHmmss";

  /**
   * @param properties Properties
   * @param exportDate Date exported
   * @return the file name of the current export.
   * @throws IOException if IO fails
   */
  public static File getExportFile(
      final Properties properties, final Date exportDate) throws IOException {
    final String p =
        properties.getProperty(
            "export.dir", System.getProperty("java.io.tmpdir"));
    final File dir = new File(p);
    final String file =
        "cesecore-"
            + FastDateFormat.getInstance(
                    EXPORTFILE_DATE_FORMAT, ValidityDateUtil.TIMEZONE_UTC)
                .format(exportDate)
            + ".log";
    File ret = new File(dir, file);
    if (LOG.isDebugEnabled()) {
      LOG.debug("Export file: " + p + file);
      LOG.debug("Export file canonical: " + ret.getCanonicalPath());
    }
    return ret;
  }

  /** Size. */
  private static final int FETCHSIZE = 1000;

  /**
   * Parameter to specify the number of logs to be fetched in each validation
   * round trip.
   *
   * @param properties Properties
   * @return log size
   */
  public static int getAuditLogValidationFetchSize(
      final Properties properties) {
    return getInt(properties, "validate.fetchsize", FETCHSIZE);
  }

  /**
   * Parameter to specify the number of logs to be fetched in each export round
   * trip.
   *
   * @param properties properties
   * @return log size
   */
  public static int getAuditLogExportFetchSize(final Properties properties) {
    return getInt(properties, "export.fetchsize", FETCHSIZE);
  }

  private static int getInt(
      final Properties properties, final String key, final int defaultValue) {
    int ret = defaultValue;
    try {
      ret = Integer.valueOf(properties.getProperty(key, String.valueOf(ret)));
    } catch (NumberFormatException e) {
      LOG.error(
          "Invalid value in "
              + key
              + ", must be decimal number. Using default "
              + defaultValue
              + ". Message: "
              + e.getMessage());
    }
    return ret;
  }
}
