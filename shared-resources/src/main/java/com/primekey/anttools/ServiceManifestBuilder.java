// 
// Decompiled by Procyon v0.5.36
// 

package com.primekey.anttools;

import java.util.Collection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.io.PrintWriter;
import java.lang.reflect.Modifier;
import java.lang.reflect.Method;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.io.File;

public class ServiceManifestBuilder
{
	private static final String META_INF = "META-INF";
	private static final String SERVICES = "services";
	private static final String CLASS_EXTENSION = ".class";

	public static void main(final String[] args) {
		final int errorCode = mainInternal(args);
		if (errorCode != 0) {
			System.exit(errorCode);
		}
	}

	static int mainInternal(final String[] args) {
		if (args.length < 2 || args.length > 3) {
			final String TAB = "     ";
			final StringBuffer out = new StringBuffer();
			out.append("DESCRIPTION:\n");
			out.append("     This command line tool inserts service manifest files into a given directory.\n");
			out.append("     It uses the following two arguments (without flags):\n");
			out.append("     (1) Path to a directory\n");
			out.append("     (2) A semicolon separated list of interfaces\n");
			out.append("     (3) (OPTIONAL) Temporary working directory, only applicable (but not required) when writing to jar. Will use system default if left blank.\n");
			out.append("\n");
			out.append("EXAMPLES:\n");
			out.append("     /usr/ejbca/modules/ejbca-ejb-cli/build/ com.foo.bar.InterfaceAlpha;com.bar.foo.InterfaceBeta /var/tmp/ \n");
			out.append("\n");
			out.append("WARNING: Adding a service manifest to a JAR with a file manifest is unstable at the moment.");
			System.err.println(out.toString());
			return 1;
		}
		final File archive = new File(args[0]);
		if (!archive.exists()) {
			System.err.println(archive + " does not exist on the system.");
			return 1;
		}
		if (archive.isFile() && !archive.getName().endsWith(".jar")) {
			System.err.println(archive + " does not appear to be a .jar file.");
			return 1;
		}
		final String cp = System.getProperty("java.class.path");
		String[] paths = cp.split(":");
		URL urls[] = new URL[paths.length];
		try {
			for (int i = 0; i < paths.length; i++) {	
				urls[i] = new File(paths[i]).toURI().toURL();
			}
		}catch (MalformedURLException e) {
			// TODO: handle exception
		}

		final URLClassLoader sysloader = new URLClassLoader(urls, ClassLoader.getSystemClassLoader());
		try {
			final Method method = URLClassLoader.class.getDeclaredMethod("addURL", URL.class);
			method.setAccessible(true);
			method.invoke(sysloader, archive.toURI().toURL());
		}
		catch (Throwable t) {
			throw new RuntimeException("Exception caught while trying to modify classpath", t);
		}
		final String[] classNames = args[1].split(";");
		final Class<?>[] classes = (Class<?>[])new Class[classNames.length];
		for (int i = 0; i < classNames.length; ++i) {
			try {
				classes[i] = Class.forName(classNames[i]);
			}
			catch (ClassNotFoundException e2) {
				System.err.println("Class " + classNames[i] + " not found on classpath, cannot continue.");
				return 1;
			}
		}
		try {
			buildServiceManifestToLocation(archive, classes);
		}
		catch (IOException e) {
			System.err.println("Disk related error occured while building manifest, see following stacktrace");
			e.printStackTrace();
			return 1;
		}
		return 0;
	}

	public static void delete(final File file) {
		if (file.isDirectory()) {
			for (final File subFile : file.listFiles()) {
				delete(subFile);
			}
		}
		if (!file.delete()) {
			System.err.println("Could not delete directory " + file.getAbsolutePath());
		}
	}

	public static File createTempDirectory() throws IOException {
		return createTempDirectory(null);
	}

	public static File createTempDirectory(final File location) throws IOException {
		final File temp = File.createTempFile("tmp", Long.toString(System.nanoTime()), location);
		if (!temp.delete()) {
			throw new IOException("Could not delete temp file: " + temp.getAbsolutePath());
		}
		if (!temp.mkdir()) {
			throw new IOException("Could not create temp directory: " + temp.getAbsolutePath());
		}
		return temp;
	}

	public static void buildServiceManifestToLocation(final File location, final Class<?>... interfaceClasses) throws IOException {
		if (!location.isDirectory()) {
			throw new IOException("File " + location + " was not a directory.");
		}
		if (!location.canWrite() && !location.canRead()) {
			throw new IOException("Could not read/write to directory " + location);
		}
		for (final Class<?> interfaceClass : interfaceClasses) {
			if (!interfaceClass.isInterface() && !Modifier.isAbstract(interfaceClass.getModifiers())) {
				throw new IllegalArgumentException("Class " + interfaceClass.getName() + " was not an interface or an asbtract class.");
			}
			final List<Class<?>> implementingClasses = getImplementingClasses(location, location, interfaceClass);
			System.out.println("Added " + implementingClasses.size() + " implementations of " + interfaceClass.getName());
			final File metaInf = new File(location, "META-INF");
			if (!metaInf.exists() && !metaInf.mkdir()) {
				throw new IOException("Could not create directory " + metaInf);
			}
			final File servicesDirectory = new File(metaInf, "services");
			if (!servicesDirectory.exists() && !servicesDirectory.mkdirs()) {
				throw new IOException("Could not create directory " + servicesDirectory);
			}
			final File manifestFile = new File(servicesDirectory, interfaceClass.getName());
			if (!manifestFile.exists() && !manifestFile.createNewFile()) {
				throw new IOException("Could not create manifest file.");
			}
			final PrintWriter printWriter = new PrintWriter(manifestFile);
			try {
				for (final Class<?> implementingClass : implementingClasses) {
					printWriter.println(implementingClass.getName());
				}
			}
			finally {
				printWriter.flush();
				printWriter.close();
			}
		}
	}

	private static List<Class<?>> getImplementingClasses(final File baseLocation, final File location, final Class<?> interfaceClass) {
		final List<Class<?>> result = new ArrayList<Class<?>>();
		if (location.isDirectory()) {
			final int baseLocationAbsolutePathLength = baseLocation.getAbsolutePath().length() + File.separator.length();
			for (final File file : location.listFiles()) {
				if (file.isDirectory()) {
					result.addAll(getImplementingClasses(baseLocation, file, interfaceClass));
				}
				else {
					final String absolutePath = file.getAbsolutePath();
					final int indexOfExtension = absolutePath.indexOf(".class");
					if (indexOfExtension != -1 && indexOfExtension == absolutePath.length() - ".class".length()) {
						final String className = absolutePath.substring(baseLocationAbsolutePathLength, indexOfExtension).replace(File.separatorChar, '.');
						try {
							final Class<?> candidate = Class.forName(className, false, ServiceManifestBuilder.class.getClassLoader());
							if (interfaceClass.isAssignableFrom(candidate) && !Modifier.isAbstract(candidate.getModifiers()) && !candidate.isInterface()) {
								result.add(candidate);
							}
						}
						catch (ClassNotFoundException e) {
							throw new IllegalArgumentException("Class of name " + className + " was not found, even though a class file" + " of that name was found in " + baseLocation.getAbsolutePath(), e);
						}
					}
				}
			}
		}
		return result;
	}
}