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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;

/**
 * Simple tool that - expands all JARs in an EAR to a temporary directory -
 * looks for all {@literal @}Stateless annotated classes - finds out what
 * {@literal @}Local interfaces the SSBs implement - looks through all SSBs' for
 * {@literal @}EJB annotated fields and builds a list of dependencies from that
 * for each SSB - traverses all dependencies to remove implied dependencies (if
 * A-&gt;B,C and B-&gt;C we can just say A-&gt;B-&gt;C) - outputs dependency
 * tree to console and a .dot-file that can be used to generate a graph.
 *
 * @version $Id: EjbDependencyGraphTool.java 22142 2015-11-03 14:15:51Z
 *     mikekushner $
 */
public class EjbDependencyGraphTool {

  /**
   * public entry point that spawns and runs a non-static version of this class.
   *
   * @param args Args
   */
  public static void main(final String[] args) {
    try {
      new EjbDependencyGraphTool().run(args);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private void run(final String[] args)
      throws IOException, ClassNotFoundException {
    if (args.length != 2) {
      log("Syntax: <EAR file> <output.dot>");
    }
    log("Extracting JARs form EAR into temp directory..");
    final File earFile = new File(args[0]);
    final JarFile earJarFile = new JarFile(earFile);
    final JarInputStream earInputStream =
        new JarInputStream(new FileInputStream(earFile));
    final List<URL> jarUrls = new ArrayList<URL>();
    final List<String> interestingClasses = new ArrayList<String>();
    JarEntry earEntry;
    while ((earEntry = earInputStream.getNextJarEntry()) != null) {
      if (earEntry.getName().endsWith(".jar")
          && !earEntry.getName().contains("systemtests")) {
        final File tempFile =
            getTempFileFromJar(earJarFile.getInputStream(earEntry));
        jarUrls.add(tempFile.toURI().toURL());
        interestingClasses.addAll(getInterestingClasses(tempFile));
      }
    }
    log("Loading potentially interesting classes..");
    @SuppressWarnings("resource") // Loader can only be closed on JDK7
    final URLClassLoader loader =
        new URLClassLoader(
            jarUrls.toArray(new URL[0]),
            this.getClass()
                .getClassLoader()); // NOPMD this is a stand-alone tools, not a
                                    // part of a JEE application
    try {
      List<BeanInfo> ejbs = new ArrayList<BeanInfo>();
      for (String className : interestingClasses) {
        Class<?> c = loader.loadClass(className);
        if (c.isAnnotationPresent(javax.ejb.Stateless.class)) {
          ejbs.add(new BeanInfo(c));
        }
      }

      log("Translating local interface dependencies into bean dependencies..");
      for (BeanInfo beanInfoToAlter : ejbs) {
        for (Class<?> dependingOnIface
            : beanInfoToAlter.interfaceDependencies) {
          for (BeanInfo beanInfoToMatch : ejbs) {
            for (Class<?> iface : beanInfoToMatch.ifaceClasses) {
              if (dependingOnIface.equals(iface)) {
                beanInfoToAlter.beanDependencies.add(beanInfoToMatch);
              }
            }
          }
        }
      }
      log("Removing implied dependencies..");
      boolean moreIterationsRequired = true;
      while (moreIterationsRequired) {
        moreIterationsRequired = false;
        for (BeanInfo currentBean : ejbs) {
          // log(" processing " + currentBean.beanClass.getSimpleName());
          final List<BeanInfo> toRemove = new ArrayList<BeanInfo>();
          for (BeanInfo dependsOn : currentBean.beanDependencies) {
            if (!toRemove.contains(dependsOn)) {
              for (BeanInfo dependsOn2 : currentBean.beanDependencies) {
                if (!toRemove.contains(dependsOn2)) {
                  if (dependsOn.dependsOnBean(dependsOn2, currentBean, 0, 10)) {
                    toRemove.add(dependsOn2);
                    moreIterationsRequired = true;
                  }
                }
              }
            }
          }
          currentBean.beanDependencies.removeAll(toRemove);
        }
      }
      // Show what we got..
      for (BeanInfo currentBean : ejbs) {
        log(currentBean.beanClass.getSimpleName());
        for (BeanInfo dep : currentBean.beanDependencies) {
          log(" -&gt; " + dep.beanClass.getSimpleName());
        }
      }
      // Create .dot-file
      final StringBuilder sb = new StringBuilder();
      sb.append(
          "digraph \""
              + args[0].substring(args[0].lastIndexOf("/") + 1)
              + "\" {\n");
      sb.append("graph [rankdir=\"BT\",nslimit=\"5.0\",mclimit=\"5.0\"];\n");
      sb.append(
          "node [fontsize=\"12\",fontname=\"Helvetica-Bold\",shape=box];\n");
      sb.append("edge [style=\"bold\"];\n");
      for (BeanInfo currentBean : ejbs) {
        sb.append(
            "\""
                + currentBean.beanClass.getSimpleName()
                + "\" [fillcolor=\"yellow\",style=\"filled,bold\""
                + ",fontname=\"Helvetica-Bold\"]\n");
        for (BeanInfo dep : currentBean.beanDependencies) {
          sb.append(
              "\""
                  + currentBean.beanClass.getSimpleName()
                  + "\" -&gt; \""
                  + dep.beanClass.getSimpleName()
                  + "\" [color=\"#000068\"]\n");
        }
      }
      sb.append("}\n");
      FileOutputStream fos = new FileOutputStream(new File(args[1]));
      try {
        fos.write(sb.toString().getBytes());
      } finally {
        fos.close();
      }
    } finally {
      // loader.close(); // close is inly available since java 7
      earInputStream.close();
      earJarFile.close();
    }
  }

  /**
   * @param jarFile JAR
   * @return a list of class-names that end with "SessionBean" (we don't want to
   *     load all classes from the EAR into the ClassLoader..)
   * @throws IOException Fail
   */
  private List<String> getInterestingClasses(final File jarFile)
      throws IOException {
    final JarInputStream jarInputStream =
        new JarInputStream(new FileInputStream(jarFile));
    try {
      final List<String> interestingClasses = new ArrayList<String>();
      JarEntry jarEntry;
      // log("    Processing " + jarFile.getName() + ":" + jarFile.length());
      while ((jarEntry = jarInputStream.getNextJarEntry()) != null) {
        final String jarEntryName = jarEntry.getName();
        if (jarEntryName.endsWith("SessionBean.class")) {
          final String className =
              jarEntryName.replaceAll(".class", "").replaceAll("/", ".");
          // log("  Matching filename: " + jarEntryName + " -&gt; " +
          // className);
          interestingClasses.add(className);
        }
      }
      return interestingClasses;
    } finally {
      jarInputStream.close();
    }
  }

  /**
   * Write JAR entry to temporary file and return a reference to this file.
   *
   * @param jarInputStream Jar
   * @return File
   * @throws IOException fail
   */
  private File getTempFileFromJar(final InputStream jarInputStream)
      throws IOException {
    final int mb = 1024 * 1024;
    final File tempFile = File.createTempFile("jee5deps-", ".jar");
    final byte[] buffer = new byte[10 * mb];
    final OutputStream os = new FileOutputStream(tempFile);
    while (jarInputStream.available() > 0) {
      final int len = jarInputStream.read(buffer);
      if (len == -1) {
        break;
      }
      os.write(buffer, 0, len);
    }
    os.close();
    return tempFile;
  }

  /**
   * Avoids dependencies on other frameworks (like log4j) by using System.out.
   *
   * @param s String
   */
  private void log(final String s) {
    System.out.println(s);
  }

  /** Class to represent a SSB and its dependencies. */
  private class BeanInfo {
        /** Param. */
    private final List<Class<?>> interfaceDependencies =
        new ArrayList<Class<?>>();
    /** Param. */
    private final List<BeanInfo> beanDependencies = new ArrayList<BeanInfo>();
    /** Param. */
    private final Class<?> beanClass;
    /** Param. */
    private final List<Class<?>> ifaceClasses = new ArrayList<Class<?>>();

    BeanInfo(final Class<?> abeanClass) {
      this.beanClass = abeanClass;
      // Find all @Local interfaces that this class implements
      for (Class<?> iface : abeanClass.getInterfaces()) {
        if (iface.isAnnotationPresent(javax.ejb.Local.class)) {
          ifaceClasses.add(iface);
          // log(" @Stateless " + beanClass.getSimpleName() + " implements
          // @Local " + iface.getSimpleName());
        }
      }
      // Find all @EJB annotated fields and add these classes as dependencies
      for (Field field : abeanClass.getDeclaredFields()) {
        if (field.isAnnotationPresent(javax.ejb.EJB.class)) {
          interfaceDependencies.add(field.getType());
          // log("   depends on " + field.getType().getSimpleName());
          if (field.getType().getName().endsWith("Remote")) {
            log(
                "   WARNING: depends on "
                    + field.getType().getSimpleName()
                    + ". @Remote interface?");
          }
        }
      }
    }

    /**
     * Recurses through all dependencies to find out if beanInfo is present in
     * any dependency.
     *
     * @param beanInfo Info
     * @param origReqBeanInfo Info
     * @param osteps Sterps
     * @param maxSteps Max
     * @return bool
     */
    public boolean dependsOnBean(
        final BeanInfo beanInfo,
        final BeanInfo origReqBeanInfo,
        final int osteps,
        final int maxSteps) {
      int steps = osteps;
      if (steps > maxSteps) {
        return false; // Don't recurse in loops forever
      }
      if (origReqBeanInfo.beanClass.equals(beanInfo.beanClass)) {
        return false; // Don't remove circular dependencies
      }
      if (beanDependencies.contains(beanInfo)) {
        return true;
      }
      for (BeanInfo bean : beanDependencies) {
        if (bean.dependsOnBean(beanInfo, origReqBeanInfo, steps++, maxSteps)) {
          return true;
        }
      }
      return false;
    }
  }
}
