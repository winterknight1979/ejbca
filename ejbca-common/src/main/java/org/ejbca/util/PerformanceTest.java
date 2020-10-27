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

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * @version $Id: PerformanceTest.java 26158 2017-07-18 05:46:19Z mikekushner $
 */
@SuppressWarnings("synthetic-access")
public class PerformanceTest {

      /** Param. */
  private final int statisticUpdatePeriodInSeconds = 10;
  /** Param. */
  private final Log log;
  /** Param. */
  private final Random random;
  /** Param. */
  private boolean isSomeThreadUsingRandom;

  /**
   * Constructor. */
  public PerformanceTest() {
    this.log = new Log();
    this.random = new Random();
    this.isSomeThreadUsingRandom = false;
  }

  /**
   * @return long
   */
  public long nextLong() {
    synchronized (this.random) {
      while (this.isSomeThreadUsingRandom) {
        try {
          this.random.wait();
        } catch (InterruptedException e) {
          // should never ever happen
          throw new Error(e);
        }
      }
      this.isSomeThreadUsingRandom = true;
      final long result = this.random.nextLong();
      this.isSomeThreadUsingRandom = false;
      this.random.notifyAll();
      return result;
    }
  }

  /**
   * @return log
   */
  public Log getLog() {
    return this.log;
  }

  /**
   * @return random
   */
  public Random getRandom() {
    return this.random;
  }

  public interface CommandFactory {
      /**
       * @return cmds
       * @throws Exception fail
       */
    Command[] getCommands() throws Exception;
  }

  public interface Command {
      /**
       * @return success
       * @throws Exception fail
       */
    boolean doIt() throws Exception;

    /**
     * @return desc
     */
    String getJobTimeDescription();
  }

  private class JobRunner
      implements Runnable { // NOPMD this is a standalone test, not run in jee
                            // app
      /** param. */
    private final Command command;
    /** param. */
    private boolean bIsFinished;
    /** param. */
    private int time;
    /** param. */
    private boolean isSuccess = false;

    JobRunner(final Command acommand) throws Exception {
      this.bIsFinished = false;
      this.command = acommand;
    }

    boolean execute() throws Exception {
      final Thread thread =
          new Thread(
              this); // NOPMD this is a standalone test, not run in jee app
      synchronized (this) {
        thread.start();
        final int fiveMins = 300 * MS_PER_S;
        if (!this.bIsFinished) {
          this.wait(fiveMins);
        }
        if (!this.bIsFinished) {
          thread.interrupt();
          throw new Exception(
              "Command not finished. See the error printout just above.");
        }
      }
      return this.isSuccess;
    }

    @Override
    public void run() {
      try {
        final long startTime = new Date().getTime();
        this.isSuccess = this.command.doIt();
        this.time = (int) (new Date().getTime() - startTime);
        this.bIsFinished = true;
      } catch (Throwable t) { // NOPMD: keep on testing
        PerformanceTest.this.log.error("Command failure. " + this.command, t);
      } finally {
        synchronized (this) {
          this.notifyAll();
        }
      }
    }

    public int getTimeConsumed() {
      return this.time;
    }
  }

  private class TestInstance
      implements Runnable { // NOPMD this is a standalone test, not run in jee
                            // app
      /** param. */
    private final int nr;
    /** param. */
    private final int maxWaitTime;
    /** param. */
    private final Statistic statistic;
    /** param. */
    private final Command[] commands;
    /**
     * @param anr NR
     * @param awaitTime Time
     * @param astatistic Stat
     * @param commandFactory Factory
     * @throws Exception On fail
     */
    TestInstance(
        final int anr,
        final int awaitTime,
        final Statistic astatistic,
        final CommandFactory commandFactory)
        throws Exception {
      this.nr = anr;
      this.maxWaitTime = awaitTime;
      this.statistic = astatistic;
      this.commands = commandFactory.getCommands();
      if (this.nr > 0) {
        return;
      }
      final StringWriter sw = new StringWriter();
      final PrintWriter pw = new PrintWriter(sw);
      pw.println(
          "Performance test started. The following \"Command\" classes are"
              + " used for each test:");
      for (int i = 0; i < this.commands.length; i++) {
        pw.println(this.commands[i].getClass().getCanonicalName());
      }
      PerformanceTest.this.log.info(sw.toString());
    }

    @Override
    public void run() {
      PerformanceTest.this.log.info("Thread nr " + this.nr + " started.");
      while (this.statistic.doMoreTests()) {
        try {
          final long startTime = new Date().getTime();
          Command failingCommand = null;
          for (int i = 0;
              failingCommand == null && i < this.commands.length;
              i++) {
            if (this.maxWaitTime > 0) {
              final int waitTime =
                  (int)
                      (this.maxWaitTime
                          * PerformanceTest.this.random.nextFloat());
              if (waitTime > 0) {
                synchronized (this) {
                  wait(waitTime);
                }
                this.statistic.addTime("Time waiting between jobs", waitTime);
              }
            }
            final Command command = this.commands[i];
            final JobRunner jobRunner = new JobRunner(command);
            if (!jobRunner.execute()) {
              failingCommand = command;
            }
            this.statistic.addTime(
                command.getJobTimeDescription(), jobRunner.getTimeConsumed());
          }
          String sResult = "Test in thread " + this.nr + " completed ";
          if (failingCommand == null) {
            this.statistic.taskFinished();
            sResult += "successfully";
          } else {
            this.statistic.taskFailed();
            sResult +=
                "but failed when the command '"
                    + failingCommand.getClass().getCanonicalName()
                    + "' was executed";
          }
          sResult +=
              ". The time it took was "
                  + (new Date().getTime() - startTime)
                  + " ms.";
          if (failingCommand == null) {
            PerformanceTest.this.log.info(sResult);
          } else {
            PerformanceTest.this.log.error(sResult);
          }
        } catch (Throwable t) { // NOPMD: keep on testing...
          this.statistic.taskFailed();
          PerformanceTest.this.log.error(
              "Exeption in thread " + this.nr + ".", t);
        }
      }
    }
  }

  /**
   * @param commandFactory fac
   * @param numberOfThreads threads
   * @param numberOfTests tests
   * @param waitTime wait
   * @param printStream output
   * @throws Exception fail
   */
  public void execute(
      final CommandFactory commandFactory,
      final int numberOfThreads,
      final int numberOfTests,
      final int waitTime,
      final PrintStream printStream)
      throws Exception {

    final Statistic statistic =
        new Statistic(numberOfThreads, numberOfTests, printStream);
    final Thread[] threads =
        new Thread
            [numberOfThreads]; // NOPMD this is a standalone test, not run in
                               // jee app
    for (int i = 0; i < numberOfThreads; i++) {
      threads[i] =
          new Thread(
              new TestInstance(
                  i,
                  waitTime,
                  statistic,
                  commandFactory)); // NOPMD this is a standalone test, not run
                                    // in jee app
    }
    for (int i = 0; i < numberOfThreads; i++) {
      threads[i].start();
    }
    new Thread(statistic)
        .start(); // NOPMD this is a standalone test, not run in jee app
    printStream.println(
        "Test client started, tail info and error files in this directory for"
            + " output.");
    printStream.println(
        "Statistic will be written to standard output each "
            + this.statisticUpdatePeriodInSeconds
            + " second.");
    printStream.println("The test was started at " + new Date());
    printStream.format(
        "%d number of threads will be started and %d number of tests will be"
            + " performed. Each thread will wait between 0 and %d milliseconds"
            + " between each test.%n",
        numberOfThreads, numberOfTests, waitTime);
    synchronized (this) {
      wait();
    }
    printStream.format(
        "Test exited with %d number of failures.%n",
        statistic.getNrOfFailures());
    System.exit(statistic.getNrOfFailures());
  }

  private class Statistic
      implements Runnable { // NOPMD this is a standalone test, not run in jee
                            // app
      /** param. */
    private final int nrOfThreads;
    /** param. */
    private final int nrOfTests;
    /** param. */
    private final Map<String, Job> jobs;
    /** param. */
    private int nrOfStarted = 0;
    /** param. */
    private int nrOfSuccesses = 0;
    /** param. */
    private int nrOfSuccessesLastTime = 0;
    /** param. */
    private int nrOfFailures = 0;
    /** param. */
    private final PrintStream printStream;

    Statistic(
        final int anrOfThreads,
        final int anrOfTests,
        final PrintStream aprintStream) {
      this.nrOfThreads = anrOfThreads;
      this.nrOfTests = anrOfTests;
      this.jobs = new HashMap<String, Job>();
      this.printStream = aprintStream;
    }

    private final class Job {
        /** param. */
      private final String name;
      /** param. */
      private long totalTime;
      /** param. */
      private long minTime = Long.MAX_VALUE;
      /** param. */
      private long maxTime = Long.MIN_VALUE;
      /** param. */
      private Date minTimeAt;
      /** param. */
      private Date maxTimeAt;

      private Job(final String aname) {
        this.name = aname;
        this.totalTime = 0;
      }

      void addTime(final long duration) {
        this.totalTime += duration;
        final Date now = new Date();

        if (duration < this.minTime) {
          this.minTime = duration;
          this.minTimeAt = now;
        }
        if (duration > this.maxTime) {
          this.maxTime = duration;
          this.maxTimeAt = now;
        }
      }

      long getTimeSpent() {
        return this.totalTime;
      }

      void printRelativeTime(final long allThreadsTime) {
        printLine(
            this.name, Float.valueOf((float) this.totalTime / allThreadsTime));
      }

      void printMinMaxTime() {
        printLine(
            "Min time for job '" + this.name + "' (ms)",
            Long.toString(this.minTime),
            this.minTimeAt);
        printLine(
            "Max time per job '" + this.name + "' (ms)",
            Long.toString(this.maxTime),
            this.maxTimeAt);
      }
    }

    private Job getJob(final String name) {
      Job job = this.jobs.get(name);
      if (job != null) {
        return job;
      }
      job = new Job(name);
      this.jobs.put(name, job);
      return job;
    }

    private boolean isNotReady() {
      return this.nrOfTests < 0
          || (this.nrOfFailures + this.nrOfSuccesses) < this.nrOfTests;
    }

    private void killMeIfReady() {
      if (isNotReady()) {
        return;
      }
      this.notifyAll();
    }

    synchronized void taskFailed() {
      this.nrOfFailures++;
      killMeIfReady();
    }

    synchronized void taskFinished() {
      this.nrOfSuccesses++;
      killMeIfReady();
    }

    synchronized boolean doMoreTests() {
      return this.nrOfTests < 0 || this.nrOfStarted++ < this.nrOfTests;
    }

    void addTime(final String timeName, final long duration) {
      getJob(timeName).addTime(duration);
    }

    private void printLine(final String description, final Object value) {
      printLine(description, value, null);
    }

    private void printLine(
        final String description, final Object value, final Object value2) {
      String padding = new String();
      final int max = 50;
      for (int i = description.length(); i < max; i++) {
        padding += ' ';
      }
      if (value2 == null) {
        this.printStream.println(description + ": " + padding + value);
      } else {
        this.printStream.println(
            description + ": " + padding + value + " (" + value2 + ")");
      }
    }

    private void printStatistics(
        final long startTime, final long periodStartTime, final long endTime) {
      final long time = (int) (endTime - startTime);
      final long allThreadsTime = this.nrOfThreads * time;
      final Float testsPerSecond =
          Float.valueOf((float) this.nrOfSuccesses * 1000 / time);
      final Float testsPerSecondInLastPeriod =
          Float.valueOf(
              (float) (this.nrOfSuccesses - this.nrOfSuccessesLastTime)
                  * 1000
                  / (endTime - periodStartTime));
      this.nrOfSuccessesLastTime = this.nrOfSuccesses;
      final float relativeWork;

        long tmp = 0;
        Iterator<Job> i = this.jobs.values().iterator();
        while (i.hasNext()) {
          tmp += i.next().getTimeSpent();
        }
        relativeWork = (float) (allThreadsTime - tmp) / allThreadsTime;

      final String csi = "\u001B[";

      this.printStream.println(
          csi + "J"); // clear rest of screen on VT100 terminals.
      printLine(
          "Total # of successfully performed tests",
          Integer.valueOf(this.nrOfSuccesses));
      printLine("Total # of failed tests", Integer.valueOf(this.nrOfFailures));
      printLine("# of tests completed each second", testsPerSecond);
      printLine(
          "# of tests completed each second in last period",
          testsPerSecondInLastPeriod);
      this.printStream.println();
      this.printStream.println(
          "Relative average time for different tasks (all should sum up to"
              + " 1):");

        i = this.jobs.values().iterator();
        while (i.hasNext()) {
          i.next().printRelativeTime(allThreadsTime);
        }

      printLine(
          "Time spent with test client work", Float.valueOf(relativeWork));
      this.printStream.println();
      this.printStream.println("Absolute extremes:");

        i = this.jobs.values().iterator();
        while (i.hasNext()) {
          i.next().printMinMaxTime();
        }

      final int len = 3;
      if (isNotReady()) { // move up if test is not finished.
        this.printStream.print(
            csi
                + (10 + this.jobs.size() * len)
                + "A"); // move up. 3 lines for each job. relative max min
      }
      this.printStream.flush();
    }

    @Override
    public void run() {
      final long startTime = new Date().getTime();
      long periodStartTime = startTime;
      while (isNotReady()) {
        synchronized (this) {
          try {
            wait(
                PerformanceTest.this.statisticUpdatePeriodInSeconds
                    * MS_PER_S);
          } catch (InterruptedException e) {
            // do nothing
          }
        }
        final long endTime = new Date().getTime();
        printStatistics(startTime, periodStartTime, endTime);
        periodStartTime = endTime;
      }
      PerformanceTest.this.log.deActivate();
    }

    public int getNrOfFailures() {
      return this.nrOfFailures;
    }
  }

  /** Ms. */
  private static final int MS_PER_S = 1000;

  public class Log {
      /** param. */
    private final PrintWriter errorPrinter;
    /** param. */
    private final PrintWriter infoPrinter;
    /** param. */
    private final PrintWriter allPrinter;
    /** param. */
    private final ObjectOutput resultObject;
    /** param. */
    private final LogThread thread;

    Log() {
      try {
        this.errorPrinter = new PrintWriter(new FileWriter("error.log"));
        this.infoPrinter = new PrintWriter(new FileWriter("info.log"));
        this.allPrinter = new PrintWriter(new FileWriter("all.log"));
        this.resultObject =
            new ObjectOutputStream(new FileOutputStream("result.log", true));
        this.thread = new LogThread();
        final Thread t =
            new Thread(
                this
                    .thread); // NOPMD this is a standalone test, not run in jee
                              // app
        t.setPriority(Thread.MIN_PRIORITY);
        t.start();
      } catch (IOException e) {
        System.out.println("Error opening log file. " + e.getMessage());
        System.exit(-1); // NOPMD this is a test cli command
        throw new Error(e);
      }
    }

    /** Close. */
    public void close() {
      this.errorPrinter.close();
      this.infoPrinter.close();
      this.allPrinter.close();
    }

    private class LogThread
        implements Runnable { // NOPMD this is a standalone test, not run in jee
                              // app
        /** param. */
      private final List<Data> lData = new LinkedList<Data>();
      /** param. */
      private boolean active = true;

      private class Data {
          /** param. */
        private final Object msg;
        /** param. */
        private final Throwable t;
        /** param. */
        private final PrintWriter printer;
        /** param. */
        private final ObjectOutput objectOutput;
        /** param. */
        private final boolean doPrintDate;

        Data(
            final Object amsg,
            final Throwable at,
            final PrintWriter aprinter,
            final ObjectOutput aobjectOutput,
            final boolean adoPrintDate) {
          this.msg = amsg;
          this.t = at;
          this.printer = aprinter;
          this.doPrintDate = adoPrintDate;
          this.objectOutput = aobjectOutput;
        }
      }

      private synchronized void log(
          final Object msg,
          final Throwable t,
          final PrintWriter printer,
          final ObjectOutput objectOutput,
          final boolean doPrintDate) {
        this.lData.add(new Data(msg, t, printer, objectOutput, doPrintDate));
        this.notifyAll();
      }

      synchronized void deActivate() {
        this.active = false;
        this.notifyAll();
      }

      void log(
          final String msg,
          final Throwable t,
          final PrintWriter printer,
          final boolean doPrintDate) {
        log(msg, t, printer, null, doPrintDate);
      }

      void log(final Object msg, final ObjectOutput objectOutput) {
        log(msg, null, null, objectOutput, false);
      }

      private void log() {
        final Data data;
        synchronized (this) {
          while (this.active && this.lData.size() < 1) {
            try {
              this.wait();
            } catch (InterruptedException e) {
              e.printStackTrace();
              System.exit(-2); // NOPMD this is a test cli command
              throw new Error(e);
            }
          }
          if (!this.active) {
            return;
          }
          data = this.lData.remove(0);
        }
        final Date currentDate = new Date();
        try {
          if (data.printer != null) {
            if (data.doPrintDate) {
              data.printer.print(currentDate + " : ");
            }
            data.printer.println(data.msg);
            if (data.t != null) {
              data.t.printStackTrace(data.printer);
              data.printer.println();
            }
            data.printer.flush();
          }
          if (data.objectOutput != null) {
            data.objectOutput.writeObject(data.msg);
          }
        } catch (IOException e) {
          error("Logging fault", e);
        }
      }

      @Override
      public void run() {
        while (this.active) {
          log();
        }
        synchronized (PerformanceTest.this) {
          // stop wait in main thread.
          PerformanceTest.this.notifyAll();
        }
      }
    }

    private void log(
        final String msg, final Throwable t, final PrintWriter printer) {
      this.thread.log(msg, t, printer, true);
    }

    /**
     * @param object obg
     */
    public void result(final Object object) {
      this.thread.log(object, this.resultObject);
    }

    /**
     * @param msg message
     * @param t cause
     */
    public void error(final String msg, final Throwable t) {
      log(msg, t, this.errorPrinter);
      log(msg, t, this.allPrinter);
    }

    /**
     * @param msg message
     */
    public void error(final String msg) {
      error(msg, null);
    }

    /**
     * @param msg message
     * @param t cause
     */
    public void info(final String msg, final Throwable t) {
      log(msg, t, this.infoPrinter);
      log(msg, t, this.allPrinter);
    }

    /**
     * @param msg Message
     */
    public void info(final String msg) {
      info(msg, null);
    }

    /** Deac. */
    public void deActivate() {
      this.thread.deActivate();
    }
  }
  /**
   * This class will be removed when the new CLI with arguments identifiers is
   * introduces.
   */
  public static class NrOfThreadsAndNrOfTests {
      /**
       * @param os string
       */
    public NrOfThreadsAndNrOfTests(final String os) {
      if (os == null) {
        this.threads = 1;
        this.tests = -1;
        return;
      }
      final String s = os.trim();
      final int sepPos = s.indexOf(':');
      if (sepPos < 0) {
        this.threads = Integer.parseInt(s);
        this.tests = -1;
        return;
      }
      this.threads = Integer.parseInt(s.substring(0, sepPos));
      this.tests = Integer.parseInt(s.substring(sepPos + 1));
    }

    /** Threds. */
    private final int threads;
    /** Tests. */
    private final int tests;
    /**
     * @return the threads
     */
    public int getThreads() {
        return threads;
    }
    /**
     * @return the tests
     */
    public int getTests() {
        return tests;
    }
  }
}
