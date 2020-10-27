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

import java.io.Serializable;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.sql.DataSource;
import org.apache.log4j.Logger;

/**
 * Helper class for reading the index meta data from the database using direct
 * JDBC.
 *
 * @version $Id: DatabaseIndexUtil.java 31557 2019-02-22 12:26:04Z anatom $
 */
public abstract class DatabaseIndexUtil {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(DatabaseIndexUtil.class);

  /**
   * Private helper class to help sorting the columns in the right order even if
   * the database would return them in a different order than the ordinal.
   */
  private static final class OrdinalColumn
          implements Comparable<OrdinalColumn> {
      /** Pos. */
    private final short ordinalPosition;
    /** Name. */
    private final String columnName;

    /**
     * @param anOrdinalPosition pos
     * @param aColumnName name
     */
    private OrdinalColumn(
        final short anOrdinalPosition, final String aColumnName) {
      this.ordinalPosition = anOrdinalPosition;
      this.columnName = aColumnName;
    }

    @Override
    public int compareTo(final OrdinalColumn other) {
      return this.ordinalPosition - other.ordinalPosition;
    }
  }

  /** Database index representation. */
  public static class DatabaseIndex implements Serializable {
    private static final long serialVersionUID = 1L;
    /** Index. */
    private final String indexName;
    /** Columns. */
    private final transient List<OrdinalColumn> ordinalColumns =
        new ArrayList<>();
    /** names. */
    private final List<String> columnNames = new ArrayList<>();
    /** boll. */
    private final boolean nonUnique;

    /**
     * @param anindexName name
     * @param isnonUnique bool
     */
    public DatabaseIndex(final String anindexName, final boolean isnonUnique) {
      this.indexName = anindexName;
      this.nonUnique = isnonUnique;
    }

    private void appendOrdinalColumn(final OrdinalColumn ordinalColumn) {
      ordinalColumns.add(ordinalColumn);
      Collections.sort(ordinalColumns);
      columnNames.clear();
      for (final OrdinalColumn current : ordinalColumns) {
        columnNames.add(current.columnName);
      }
    }

    /** @return the name of the index as reported by the database */
    public String getIndexName() {
      return indexName;
    }

    /**
     * @return the column names in the correct order as reported by the database
     */
    public List<String> getColumnNames() {
      return columnNames;
    }

    /** @return true if the index is reported as unique */
    public boolean isUnique() {
      return !nonUnique;
    }

    /**
     * Case insensitive check if all columns present in the argument is also
     * exactly present in this index.
     *
     * @param thecolumnNames columns
     * @return bool
     */
    public boolean isExactlyOverColumns(final List<String> thecolumnNames) {
      final List<String> indexColumnNames = new ArrayList<>();
      for (final String indexColumnName : getColumnNames()) {
        indexColumnNames.add(indexColumnName.toLowerCase());
      }
      for (final String columnName : thecolumnNames) {
        if (!indexColumnNames.remove(columnName.toLowerCase())) {
          return false;
        }
      }
      return indexColumnNames.isEmpty();
    }
  }

  /**
   * @param dataSource DS
   * @param tableName Table
   * @param columnNames Columns
   * @param requireUnique bool
   * @return true if there exists an index on the specified table exactly
   *     matches the requested columns and optionally is unique. null if the
   *     check was inconclusive.
   */
  public static Boolean isIndexPresentOverColumns(
      final DataSource dataSource,
      final String tableName,
      final List<String> columnNames,
      final boolean requireUnique) {
    if (dataSource != null) {
      try {
        final List<DatabaseIndex> databaseIndexes =
            getDatabaseIndexFromTable(dataSource, tableName, requireUnique);
        if (databaseIndexes.isEmpty()) {
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Failed to read any index meta data from the database for"
                    + " table '"
                    + tableName
                    + "'. At least a primary key index was expected.");
          }
        } else {
          for (final DatabaseIndex databaseIndex : databaseIndexes) {
            if (databaseIndex.isExactlyOverColumns(columnNames)) {
              return Boolean.TRUE;
            }
          }
          return Boolean.FALSE;
        }
      } catch (SQLException e) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Failed to read index meta data from the database for table '"
                  + tableName
                  + "'.",
              e);
        }
      }
    }
    return null;
  }

  /**
   * @param dataSource DS
   * @param tableName Table
   * @param requireUnique bool
   * @return a list of representations of each database index present for a
   *     table
   * @throws SQLException fail
   */
  public static List<DatabaseIndex> getDatabaseIndexFromTable(
      final DataSource dataSource,
      final String tableName,
      final boolean requireUnique)
      throws SQLException {
    final List<DatabaseIndex> ret = new ArrayList<>();
    try (Connection connection = dataSource.getConnection(); ) {
      final DatabaseMetaData databaseMetaData = connection.getMetaData();
      /*
       * Table names are case sensitive on at least Oracle XE
       *  (upper case) and MySQL 5.5 (camel case).
       *
       * On MySQL the "catalog" is the database.
       * On Oracle XE the username used to access the db is the schema.
       *
       * This is an attempt at a very defensive version where we assume as
        * ittle as possible about the database and it's configuration.
       */
      final Map<String, DatabaseIndex> tableIndexMap = new HashMap<>();
      // First try the simple case that has been shown to work on MariaDB 5.5
      // (but where the returned table name apparently does not work)
      tableIndexMap.putAll(
          getDatabaseIndexMap(
              databaseMetaData, null, null, tableName, requireUnique));
      // If this failed, try the searching for the table as returned by the
      // database meta data
      if (tableIndexMap.isEmpty()) {
        LOG.trace(
            "Looking up all available tables available in the datasource to"
                + " find a matching table.");
        try (ResultSet resultSetSchemas =
            databaseMetaData.getTables(null, null, null, null)) {
          while (resultSetSchemas.next()) {
            final String tableCatalog = resultSetSchemas.getString("TABLE_CAT");
            final String tableSchema =
                resultSetSchemas.getString("TABLE_SCHEM");
            final String tableName2 = resultSetSchemas.getString("TABLE_NAME");
            final String tableType = resultSetSchemas.getString("TABLE_TYPE");
            if (LOG.isTraceEnabled()) {
              LOG.trace(
                  " catalog: "
                      + tableCatalog
                      + " tableSchema: "
                      + tableSchema
                      + " tableName: "
                      + tableName2
                      + " tableType: "
                      + tableType);
            }
            if ("TABLE".equals(tableType.toUpperCase(Locale.ENGLISH))
                && tableName
                    .toUpperCase(Locale.ENGLISH)
                    .equals(tableName2.toUpperCase(Locale.ENGLISH))) {
              if (LOG.isDebugEnabled()) {
                LOG.debug(
                    "Will perform index detection on "
                        + tableType
                        + " in catalog "
                        + null
                        + " schema "
                        + null
                        + " table '"
                        + tableName2
                        + "'.");
              }
              tableIndexMap.putAll(
                  getDatabaseIndexMap(
                      databaseMetaData, null, null, tableName2, requireUnique));
              if (tableIndexMap.isEmpty()) {
                // Fall-back since null arguments apparently did not match the
                // table and assume that this will find the correct one
                if (LOG.isDebugEnabled()) {
                  LOG.debug(
                      "Will perform index detection on "
                          + tableType
                          + " in catalog '"
                          + tableCatalog
                          + "' schema '"
                          + tableSchema
                          + "' table '"
                          + tableName2
                          + "'.");
                }
                tableIndexMap.putAll(
                    getDatabaseIndexMap(
                        databaseMetaData,
                        tableCatalog,
                        tableSchema,
                        tableName2,
                        requireUnique));
              }
              break;
            }
          }
        }
      }
      ret.addAll(tableIndexMap.values());
    }
    return ret;
  }

  /**
   * @param databaseMetaData Metadata
   * @param catalog Catalog
   * @param schemaName Schema
   * @param tableName Table
   * @param requireUnique Bool
   * @return a Map of index name and the index representations of each database
   *     index present for a schema and table
   * @throws SQLException Error
   */
  private static Map<String, DatabaseIndex> getDatabaseIndexMap(
      final DatabaseMetaData databaseMetaData,
      final String catalog,
      final String schemaName,
      final String tableName,
      final boolean requireUnique)
      throws SQLException {
    final Map<String, DatabaseIndex> tableIndexMap = new HashMap<>();
    // http://docs.oracle.com/javase/7/docs/api/java/sql/DatabaseMetaData.html
    // #getIndexInfo(java.lang.String,%20java.lang.String,
    // %20java.lang.String,%20boolean,%20boolean)
    try (ResultSet resultSet =
        databaseMetaData.getIndexInfo(
            catalog,
            schemaName,
            tableName,
            requireUnique,
            /*approximate=*/ true); ) {
      while (resultSet.next()) {
        final String indexName = resultSet.getString("INDEX_NAME");
        if (indexName == null) {
          LOG.trace("Ignoring index of type tableIndexStatistic.");
          continue;
        }
        final boolean nonUnique = resultSet.getBoolean("NON_UNIQUE");
        if (!tableIndexMap.containsKey(indexName)) {
          tableIndexMap.put(indexName, new DatabaseIndex(indexName, nonUnique));
        }
        final DatabaseIndex databaseIndex = tableIndexMap.get(indexName);
        final String columnName = resultSet.getString("COLUMN_NAME");
        final short ordinalPosition = resultSet.getShort("ORDINAL_POSITION");
        databaseIndex.appendOrdinalColumn(
            new OrdinalColumn(ordinalPosition, columnName));
        if (LOG.isDebugEnabled()) {
          // Extract additional info if we are debug logging
          final short type = resultSet.getShort("TYPE");
          final String typeString;
          switch (type) {
            case DatabaseMetaData.tableIndexStatistic:
              typeString = "tableIndexStatistic";
              break;
            case DatabaseMetaData.tableIndexClustered:
              typeString = "tableIndexClustered";
              break;
            case DatabaseMetaData.tableIndexHashed:
              typeString = "tableIndexHashed";
              break;
            case DatabaseMetaData.tableIndexOther:
              typeString = "tableIndexOther";
              break;
            default:
              typeString = "unknown";
          }
          LOG.debug(
              "Detected part of index on table '"
                  + tableName
                  + "' indexName: "
                  + indexName
                  + " column["
                  + ordinalPosition
                  + "]: "
                  + columnName
                  + " unique: "
                  + !nonUnique
                  + " type: "
                  + typeString
                  + " current columns: "
                  + Arrays.toString(databaseIndex.getColumnNames().toArray()));
        }
      }
    }
    return tableIndexMap;
  }
}
