//
// Decompiled by Procyon v0.5.36
//

package com.primekey.anttools;

import java.util.ArrayList;
import java.util.List;
import java.io.PrintWriter;
import java.lang.reflect.Modifier;
import java.io.IOException;
import java.io.File;

public final class ServiceManifestBuilder {

    private ServiceManifestBuilder() {
    }

    /**
     * Entry point.
     *
     * @param args arguments
     */

    public static void main(final String[] args) {
        final int errorCode = mainInternal(args);
        if (errorCode != 0) {
            System.exit(errorCode); // NOPMD - this app is run from CLI
        }
    }

    private static int mainInternal(final String[] args) {
    	final int maxArgs = 3;
        if (args.length < 2 || args.length > maxArgs) {
            final StringBuffer out = new StringBuffer();
            out.append("DESCRIPTION:\n");
            out.append("     This command line tool inserts service manifest "
                + "files into a given directory.\n");
            out.append("     It uses the following two arguments "
                + "(without flags):\n");
            out.append("     (1) Path to a directory\n");
            out.append("     (2) A semicolon separated list of interfaces\n");
            out.append("     (3) (OPTIONAL) Temporary working directory, only "
                + "applicable (but not required) when writing to jar. "
                + "Will use system default if left blank.\n");
            out.append("\n");
            out.append("EXAMPLES:\n");
            out.append("     /usr/ejbca/modules/ejbca-ejb-cli/build/ "
                    + "com.foo.bar.InterfaceAlpha;com.bar.foo.InterfaceBeta "
                    + "/var/tmp/ \n");
            out.append("\n");
            out.append("WARNING: Adding a service manifest to a JAR with a "
                + "file manifest is unstable at the moment.");
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
        /*
         * We shouldn't need to hack the classpath because Maven automatically
         * adds the
         * output directory
         */
        final String[] classNames = args[1].split(";");
        final Class<?>[] classes = new Class[classNames.length];
        for (int i = 0; i < classNames.length; ++i) {
            try {
                classes[i] = Class.forName(classNames[i]);
            } catch (ClassNotFoundException e2) {
                System.err.println("Class " + classNames[i]
                    + " not found on classpath, cannot continue.");
                return 1;
            }
        }
        try {
            buildServiceManifestToLocation(archive, classes);
        } catch (IOException e) {
            System.err.println("Disk related error occured while building "
                + "manifest, see following stacktrace");
            e.printStackTrace();
            return 1;
        }
        return 0;
    }

    /**
     * Delete the file.
     * @param file File
     */
    public static void delete(final File file) {
        if (file.isDirectory()) {
            for (final File subFile : file.listFiles()) {
                delete(subFile);
            }
        }
        if (!file.delete()) {
            System.err.println("Could not delete directory "
                + file.getAbsolutePath());
        }
    }

    /**
     * Create a temporary directory.
     * @return Path to temp directory
     * @throws IOException If creation fails
     */
    public static File createTempDirectory() throws IOException {
        return createTempDirectory(null);
    }

    /**
     * Create temp directory in specified location.
     * @param location Location
     * @return Path
     * @throws IOException If creation fails
     */
    public static File createTempDirectory(final File location)
        throws IOException {
        final File temp = File.createTempFile("tmp",
            Long.toString(System.nanoTime()), location);
        if (!temp.delete()) {
            throw new IOException("Could not delete temp file: "
                + temp.getAbsolutePath());
        }
        if (!temp.mkdir()) {
            throw new IOException("Could not create temp directory: "
                + temp.getAbsolutePath());
        }
        return temp;
    }

    /**
     * Build the service manifest.
     * @param location Output file
     * @param interfaceClasses Classes to document
     * @throws IOException On fail
     */
    public static void buildServiceManifestToLocation(final File location,
        final Class<?>... interfaceClasses)
            throws IOException {
        testIsDirectory(location);
        testCanReadWrite(location);
        for (final Class<?> interfaceClass : interfaceClasses) {
            testIsInterface(interfaceClass);
            final List<Class<?>> implementingClasses
                = getImplementingClasses(location, location, interfaceClass);
            System.out
                    .println("Added " + implementingClasses.size()
                        + " implementations of " + interfaceClass.getName());
            final File metaInf = new File(location, "META-INF");
            testMetaInf(metaInf);
            final File servicesDirectory = new File(metaInf, "services");
            testServiceDir(servicesDirectory);
            final File manifestFile
                = new File(servicesDirectory, interfaceClass.getName());
            testManifest(manifestFile);
            final PrintWriter printWriter = new PrintWriter(manifestFile);
            try {
                for (final Class<?> implementingClass : implementingClasses) {
                    printWriter.println(implementingClass.getName());
                }
            } finally {
                printWriter.flush();
                printWriter.close();
            }
        }
    }

	private static void testManifest(final File manifestFile) 
			throws IOException {
		if (!manifestFile.exists() && !manifestFile.createNewFile()) {
		    throw new IOException("Could not create manifest file.");
		}
	}

	private static void testServiceDir(final File servicesDirectory) 
			throws IOException {
		if (!servicesDirectory.exists() && !servicesDirectory.mkdirs()) {
		    throw new IOException("Could not create directory "
		        + servicesDirectory);
		}
	}

	private static void testMetaInf(final File metaInf) throws IOException {
		if (!metaInf.exists() && !metaInf.mkdir()) {
		    throw new IOException("Could not create directory " + metaInf);
		}
	}

	private static void testIsInterface(final Class<?> interfaceClass) {
		if (!interfaceClass.isInterface()
		        && !Modifier.isAbstract(interfaceClass.getModifiers())) {
		    throw new IllegalArgumentException(
		            "Class " + interfaceClass.getName()
		                + " was not an interface or an asbtract class.");
		}
	}

	private static void testCanReadWrite(final File location) 
			throws IOException {
		if (!location.canWrite() && !location.canRead()) {
            throw new IOException("Could not read/write to directory "
                + location);
        }
	}

	private static void testIsDirectory(final File location) 
			throws IOException {
		if (!location.isDirectory()) {
            throw new IOException("File " + location + " was not a directory.");
        }
	}

    private static List<Class<?>> getImplementingClasses(
            final File baseLocation,
            final File location,
            final Class<?> interfaceClass) {
        final List<Class<?>> result = new ArrayList<Class<?>>();
        if (location.isDirectory()) {
            final int baseLocationAbsolutePathLength
                = baseLocation.getAbsolutePath().length()
                    + File.separator.length();
            for (final File file : location.listFiles()) {
                if (file.isDirectory()) {
                    result.addAll(getImplementingClasses(
                        baseLocation, file, interfaceClass));
                } else {
                    final String absolutePath = file.getAbsolutePath();
                    final int indexOfExtension = absolutePath.indexOf(".class");
                    if (indexOfExtension != -1
                        && indexOfExtension == absolutePath.length()
                            - ".class".length()) {
                        final String className = absolutePath
                                .substring(baseLocationAbsolutePathLength,
                                    indexOfExtension)
                                .replace(File.separatorChar, '.');
                        try {
                            final Class<?> candidate = Class.forName(
                                className,
                                false,
                                ServiceManifestBuilder.class.getClassLoader());
                            if (interfaceClass.isAssignableFrom(candidate)
                                    && !Modifier.isAbstract(
                                            candidate.getModifiers())
                                    && !candidate.isInterface()) {
                                result.add(candidate);
                            }
                        } catch (ClassNotFoundException e) {
                            throw new IllegalArgumentException(
                                    "Class of name "
                                    + className
                                    + " was not found, even though a class file"
                                    + " of that name was found in "
                                    + baseLocation.getAbsolutePath(), e);
                        }
                    }
                }
            }
        }
        return result;
    }
}
