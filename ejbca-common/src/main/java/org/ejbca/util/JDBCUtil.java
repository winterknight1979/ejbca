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

package org.ejbca.util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.sql.DataSource;
import org.apache.log4j.Logger;
import org.ejbca.config.DatabaseConfiguration;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ServiceLocatorException;

/**
 * Utility methods for jdbc calls.
 *
 * <p>close() methods do not close quietly but log errors (exceptions) as
 * warning. Closing quietly could mask potential errors that could have no
 * impact depending on GC stress conditions, or simply exhaust database
 * resources, so it is better to have some warning than nothing at all.
 *
 * @version $Id: JDBCUtil.java 24766 2016-11-18 13:12:02Z jeklund $
 */
public final class JDBCUtil {

    private JDBCUtil() { }
    /**
     * Log.
     */
  private static final Logger LOG = Logger.getLogger(JDBCUtil.class);

  public interface Preparer {
      /**
       * @param ps statement
       * @throws Exception fail
       */
    void prepare(PreparedStatement ps) throws Exception;

    /**
     * @return string
     */
    String getInfoString();
  }

  /**
   * @param sqlCommandTemplate Command
   * @param preparer Preparer
   * @param dataSource DS
   * @return the current result as an update count; -1 if the current result is
   *     a ResultSet object or there are no more results
   * @throws Exception On fail
   */
  public static int execute(
      final String sqlCommandTemplate,
      final Preparer preparer,
      final String dataSource)
      throws Exception {
    if (sqlCommandTemplate != null) {
      Connection connection = null;
      PreparedStatement ps = null;
      try {
        connection =
            ServiceLocator.getInstance()
                .getDataSource(dataSource)
                .getConnection();
        ps = connection.prepareStatement(sqlCommandTemplate);
        preparer.prepare(ps);
        ps.execute();
        return ps.getUpdateCount();
      } finally {
        JDBCUtil.close(connection, ps, null);
      }
    }
    return -1;
  }

  /**
   * @param sqlCommandTemplate template
   * @param preparer preparer
   * @param dataSource SD
   * @return response
   * @throws Exception error
   */
  public static String executeSelectString(
      final String sqlCommandTemplate,
      final Preparer preparer,
      final String dataSource)
      throws Exception {
    String ret = null;
    if (sqlCommandTemplate != null) {
      Connection connection = null;
      ResultSet result = null;
      PreparedStatement ps = null;
      try {
        connection =
            ServiceLocator.getInstance()
                .getDataSource(dataSource)
                .getConnection();
        ps = connection.prepareStatement(sqlCommandTemplate);
        preparer.prepare(ps);
        if (ps.execute()) {
          result = ps.getResultSet();
          if (result.next()) {
            ret = result.getString(1);
          }
        }
      } finally {
        JDBCUtil.close(connection, ps, result);
      }
    }
    return ret;
  }

  /**
   * Return the requested datasource name. It assumes that the dsName returns a
   * reference (java.lang.String) to the real datasource instance, otherwise
   * you're likely to get a ClassCastException.
   *
   * @return the requested datasource
   * @throws ServiceLocatorException if there is an error locating the
   *     datasource
   */
  public static DataSource getDataSource() throws ServiceLocatorException {
    // String dataSourceName = ServiceLocator.getInstance().getString(dsName);
    String dataSourceName = DatabaseConfiguration.getFullDataSourceJndiName();
    return ServiceLocator.getInstance().getDataSource(dataSourceName);
  }

  /**
   * Return the requested datasource name. It assumes that the dsName returns a
   * reference (java.lang.String) to the real datasource instance, otherwise
   * you're likely to get a ClassCastException.
   *
   * @return the requested datasource or null if it could not be located
   */
  public static DataSource getDataSourceOrNull() {
    final String dataSourceName =
        DatabaseConfiguration.getFullDataSourceJndiName();
    try {
      return ServiceLocator.getInstance().getDataSource(dataSourceName);
    } catch (ServiceLocatorException e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Unable to get the DataSource '" + dataSourceName + "'.", e);
      }
    }
    return null;
  }

  /**
   * return a requested database connection.
   *
   * @return a database connection
   * @throws ServiceLocatorException if it cannot get the datasource connection
   * @see #getDataSource
   */
  public static Connection getDBConnection() throws ServiceLocatorException {
    try {
      return getDataSource().getConnection();
    } catch (SQLException e) {
      throw new ServiceLocatorException("Error while getting db connection", e);
    }
  }

  /**
   * Close a db connection logging closing errors as warning.
   *
   * @param con the connection to close (can be null)
   */
  public static void close(final Connection con) {
    if (con != null) {
      try {
        con.close();
      } catch (SQLException e) {
        LOG.warn("Could not close connection", e);
      }
    }
  }

  /**
   * Close a resultset logging closing errors as warning.
   *
   * @param rs the resultset to close (can be null)
   */
  public static void close(final ResultSet rs) {
    if (rs != null) {
      try {
        rs.close();
      } catch (SQLException e) {
        LOG.warn("Could not close ResultSet", e);
      }
    }
  }

  /**
   * Close a prepared statement logging closing errors as warning.
   *
   * @param ps the prepared statement to close (can be null)
   */
  public static void close(final PreparedStatement ps) {
    if (ps != null) {
      try {
        ps.close();
      } catch (SQLException e) {
        LOG.warn("Could not close PreparedStatement", e);
      }
    }
  }

  /**
   * Close a connection, prepared statement and result set, logging potential
   * closing errors as warning.
   *
   * @param con the connection to close (can be null)
   * @param ps the prepared statement to close (can be null)
   * @param rs the result set to close (can be null)
   */
  public static void close(
      final Connection con, final PreparedStatement ps, final ResultSet rs) {
    close(rs);
    close(ps);
    close(con);
  }
  /**
   * Check if a certain column exists in the database.
   *
   * @param con the connection to use, not closed by this method
   * @param table the table where the column perhaps exists
   * @param col the name of the column to check for
   * @return true if the column exists, falst if not (the database throws an
   *     SQLException)
   */
  public static boolean columnExists(
      final Connection con, final String table, final String col) {
    PreparedStatement st = null;
    try {
      st =
          con.prepareStatement(
              "select " + col + " from " + table + " where 1=0");
      st.executeQuery();
      return true;
    } catch (SQLException e) {
      return false;
    } finally {
      JDBCUtil.close(st);
    }
  }
}
