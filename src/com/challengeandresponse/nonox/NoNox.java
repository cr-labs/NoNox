package com.challengeandresponse.nonox;

/*
 * <p>NoNox watches log files for events such as "failed password". When such a pattern is seen several 
 * times within a specified time period (for example, 4 failed login attempts within 10 minutes) 
 * from the same source, NoNox can execute a command to mitigate the behavior, notify someone, or 
 * make a record of the event (or all these things). The patterns, time limits, files to monitor, 
 * and commands that can be triggered are all user-specified, so NoNox can be used to detect many 
 * kinds of events and to respond in a variety of ways. I use NoNox to monitor for password-scanning 
 * attacks, and to block attacking hosts at the firewall in real-time.</p>
 * 
 * <P>
 * This is the script i use to launch it after compiling and stuffing into a jar file:<br>
 * start.sh:<br>
 * #!/bin/bash<br>
 * java -cp /usr/local/nonox/nonox-1.17.jar com.challengeandresponse.nonox.NoNox >> /var/log/nonox.log &
 * </p>
 * 
 * Created on Aug 2, 2005 Version 1.0
 * Last revision Nov. 26, 2005 Version 1.17
 * Documentation update Nov 11, 2007
 *
 * (c) 2005 Challenge/Response, LLC
 * @author Jim Youll, Challenge/Response LLC, jim@cr-labs.com
 *
 * LICENSE
 * 
 * This software is licensed under the CC-GNU GPL.
 * License details: http://creativecommons.org/licenses/GPL/2.0/
 *
 * Copyright (C) 2005-2007 Challenge/Response, LLC
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * 
 */

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Date;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Stack;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class NoNox {
    
    public static final String VERSION = "1.18 of 2005-11-26";

    /** The default config file, if the -c parameters was not given at startup */
    public static final String CONFIG_FILE_DEFAULT = "/usr/local/nonox/nonox.conf";
    
    /** Scan pause-interval when there IS data... to avoid too tight a loop */
    static final int LOOP_PAUSE_MSEC = 5;
    
    /**
     * Initial delay between runs of the reaper thread. This will be adjusted to the shortest TTL for active records.
     * This delay can be really, really long because it just removes held state for conditions that could no longer
     * fire an action, and there won't be millions of those... provided the patterns and rules aren't too madly
     * general.
     */
    static final long REAPER_INITIAL_DELAY_SEC = 60*30;

    
    /**
     * Every this-many seconds, close and re-open the underlying files that are bound to patterns. 
     * Set to 0 to disable periodic file re-opens.
     * This value must be at least as large as FILE_REOPEN_TIME_MINIMUM_MSEC or it will be ignored.
     * Here it's set to 1 hour.
     */
    static final long FILE_REOPEN_TIME_MSEC = 60*60*1000;
       
    /**
     * If doing file reopens, the reopen interval must be at least as large as this setting, or reopens will
     * not occur (to prevent massive thrashing). Here it's set to 10 minutes
     */
    static final long FILE_REOPEN_TIME_MINIMUM_MSEC = 60*10*1000;
    
    
    private static void sleep(int _msec) {
        try {
            Thread.sleep(_msec);
        }
        catch (InterruptedException ie) {
        }
    }
    
    
    private static void writeLog(String _s) {
        System.out.println((new Date())+" "+_s);
    }
    
    
    public static void main (String[] params) {
        
        // the tally records are here
        Hashtable<String, ActionCounter> counters = new Hashtable<String, ActionCounter>();	

        // the config file path and file name. This could be overridden by the command line paramter -c
        String configFile = CONFIG_FILE_DEFAULT;
        
        // testMode is enabled with the command line argument -t (meaning "set test mode")
        // if testMode is true, the commands that would be triggered are displayed, but not actually executed. Good for debugging roles
        boolean testMode = false;
        
        // tailMode is disabled with the command line argument -f (meaning "full file")
        // if tailMode is true, then the file is TAILed - NoNox seeks to EOF before processing any content. This is the default.
        // if tailMode is false, then NoNox processes the entire log file at startup then tails the file.
        // this is useful if you have a log that NoNox hasn't operated against,
        // or if your actions (e.g. firewall rules) are transient and aren't saved when set, e.g. with iptables-save
        boolean tailMode = true;
        
        // debugMode is enabled with the command line argument -d
        // if debugMode is true, additional details about what the program is doing will be printed to the output
        boolean debugMode = false;
        

        // to hold the patterns and actions found in the config file
        Vector<PatternConfig> patterns = new Vector<PatternConfig>();
        Vector<ActionConfig> actions = new Vector<ActionConfig>();

        // GO
        boolean running = true;
        writeLog("NoNox version "+VERSION+" started. Read loop will pause:"+LOOP_PAUSE_MSEC+" msec between read cycles (hardcoded, sorry!)");

        // first retrieve parameters, if any
        // We recognize "-c /path/to/config_file" to use a config file other than the default
        // and -t for test mode (no commands are executed when in test mode)
        // and -f to process the FULL FILE rather than starting processing at EOF (equivalent to tailing the file)
		// and -d for DEBUG MODE where lots of extra operating detail is written to stdout while the program is running
        for (int i = 0; i < params.length; i++) {
            String p = params[i].trim().toLowerCase();
            if (p.equals("-t"))
                testMode = true;
            else if (p.equals("-f"))
                tailMode = false;
            else if (p.equals("-d"))
                debugMode = true;
            else if (p.equals("-c") && ( (i+1) < params.length))
                    configFile = params[++i];
        }
        
        writeLog("configuration parameters: "+" testMode="+testMode+"; tailMode="+tailMode+"; debugMode="+debugMode);
        
        writeLog("Using config file:"+configFile);
        
        
        // LOAD SETTINGS FROM CONFIG FILE
        // build hashtables of the found patterns and actions
        // the format for the file is...
        // pattern	 	(pattern_name) 	(file) 	(regex) 
        // action			(pattern_name)	(threshold_count)	(timelimit_seconds)		(command)
        final String PATTERN_REGEX = "^(pattern)\\s*(\\S*)\\s*(\\S*)\\s*(.*)";
        final String ACTION_REGEX = "^(action)\\s*(\\S*)\\s*(\\S*)\\s*(\\S*)\\s*(.*)";
        final Pattern patternPattern = Pattern.compile(PATTERN_REGEX);
        final Pattern actionPattern = Pattern.compile(ACTION_REGEX);
        
        BufferedReader cfr = null;
        String line = null;
        try {
            cfr = new BufferedReader(new FileReader(configFile));
            
            // read the whole contents and process
            while ( (line = cfr.readLine()) != null) {
                line = line.trim();
               
                // if it's a comment, skip
                if (line.indexOf("#") == 0) 
                    continue;
                // not a comment, so process the line
                // is it a PATTERN declaration?
                if (debugMode)
                    writeLog("Processing non-comment: "+line);

                PatternConfig pcTemp = null;
                Matcher m = patternPattern.matcher(line);
                if (m.matches()) {
                    try {
                        pcTemp = new PatternConfig(m.group(2),m.group(3),tailMode,m.group(4));
                    }
                    catch (FileNotFoundException fnfe) {
                        writeLog("File not found for pattern:"+m.group(2)+" file:"+m.group(3)+" This pattern will NOT be used");
                        continue;
                    }
                    catch (IOException ioe) {
                        writeLog("IO Exception seeking to EOF for pattern:"+m.group(2)+" file:"+m.group(3)+" This pattern will NOT be used");
                        continue;
                    }
                    // continue with the next one
                    patterns.add(pcTemp);
                    writeLog("loaded pattern:"+pcTemp);
                    continue;
                }
                // is it an ACTION declaration?
                m = actionPattern.matcher(line);
                int thresholdCount;
                int timelimitSeconds;
                if (m.matches()) {
                    try {
                        thresholdCount = Integer.parseInt(m.group(3));
                        timelimitSeconds = Integer.parseInt(m.group(4));
                    }
                    catch (NumberFormatException nfe) {
                        writeLog("Exception parsing integer values from config line:"+line+" This action will NOT be used");
                        continue;
                    }
                    ActionConfig acTemp = new ActionConfig(m.group(2),thresholdCount,timelimitSeconds,m.group(5));
                    actions.add(acTemp);
                    writeLog("loaded action:"+acTemp);
                    continue;
                }
            } // end of while
            cfr.close();
            if (debugMode)
                writeLog("Config file read and closed");
        }
        catch (FileNotFoundException fnfe) {
            writeLog("Config file not found:"+configFile);
            running = false;
        }
        catch (IOException ioe) {
            writeLog("IO Exception reading config file:"+configFile+" "+ioe.getMessage());
            running = false;
        }
        
        if (   (FILE_REOPEN_TIME_MSEC != 0) &&
               (FILE_REOPEN_TIME_MSEC > FILE_REOPEN_TIME_MINIMUM_MSEC) )  {
            writeLog("Files will be closed and reopened every "+FILE_REOPEN_TIME_MSEC+" msec ("+FILE_REOPEN_TIME_MSEC/60/1000+" minutes)");
        }
        
        writeLog("Starting reaper thread");
        Reaper reaper = new Reaper(REAPER_INITIAL_DELAY_SEC,counters);
        reaper.start();

        writeLog("Starting monitor loop");
        try {
            while (running) {
                // sleep every time around just to avoid real crazy too-tight loops if it's busy
                sleep(LOOP_PAUSE_MSEC);
                
                // For all the patternconfigs, read a line from their respective files, using their readers
                // and see if there is a match
                // when a pattern matches, find all the ACTIONS that name that pattern
                // increment the counter for those ACTIONs
                // when an action goes over-threshold within timelimitSeconds, invoke it
                for (Iterator<PatternConfig> iPattern = patterns.iterator(); iPattern.hasNext(); ) {
                    PatternConfig pc = iPattern.next();
                    // If we are doing file-reopens, see if the file should be reopened. Do so, if it's time to...
                    // we don't to file reopens if FILE_OPEN_TIME_MSEC is 0, or if it's less than FILE_OPEN_TIME_MINIMUM_MSEC
                    if (	  (FILE_REOPEN_TIME_MSEC != 0) &&
                            (FILE_REOPEN_TIME_MSEC > FILE_REOPEN_TIME_MINIMUM_MSEC) &&
                            ((System.currentTimeMillis() - FILE_REOPEN_TIME_MSEC) > pc.fileOpenTimestamp)
                        )
                        pc.reopen();
                    // fetch a line from the input file
                    line = pc.br.readLine();
                    if (line == null)
                        continue; // in other words, there was nothing to read
                    if (debugMode)
                        writeLog("checking line: "+line);
                    Matcher m = pc.compiledPattern.matcher(line);
                    // if a pattern matched, step thru the actions that name the pattern, increment their
                    // counters, and invoke them if the threshold was reached
                    if (m.matches()) {
                        String  ipAddress = (m.groupCount() >= 2) ? m.group(2).trim() : "NONE";
                        // try all the actions against this rule
                        for (Iterator<ActionConfig> iActions = actions.iterator(); iActions.hasNext(); ) {
                            ActionConfig ac = iActions.next();
                            // if this Action names the current pattern, increment and optionally invoke it
                            if (! ac.patternName.equals(pc.patternName))
                                continue;
                            // every pattern + ip + action has a counter
                            String key =  ac.patternName + ipAddress + ac.index;
                            // do we have a counter for this key? If not, make a new entry
                            ActionCounter aco = null;
                            if (! counters.containsKey(key)) {
                                aco = new ActionCounter(ac.thresholdCount,ac.timelimitSeconds);
                                counters.put(key,aco);
                            } 
                            else
                                aco = (ActionCounter) counters.get(key);
                            // move on if this rule already fired
                            if (aco.fired)
                                continue;
                            // otherwise tally and see if we can fire now
                            aco.pushTimestamp(System.currentTimeMillis());
                            counters.put(key,aco);
                            writeLog("MATCH pattern:"+pc.patternName+" count:"+aco.timestamps.size()+" action:"+ac.index+" address:"+ipAddress+" source:"+line);
                            if (testMode) {
                                if (m.groupCount() >= 1) 
                                    System.out.println("date: "+m.group(1));
                                if (m.groupCount() >= 2)
                                    System.out.println("ip: "+m.group(2));
                            }
                            if (aco.canFire()) {
                                StringBuffer sb = new StringBuffer(ac.command);
                                int repl = sb.indexOf("%s");
                                if (repl > -1)
                                    sb.replace(repl,repl+2,ipAddress);
                                writeLog("ACTION running command:"+sb.toString());
                                // mark the action as FIRED: we will only try to run an action one time (to avoid real meltdowns if there is a problem with the associated command)
                                aco.fired = true;
                                // clear out the action's timestamps stack: no longer needed
                                aco.timestamps = null;
                                counters.put(key,aco);
                                Process pr = null;
                                if (testMode)
                                    writeLog("TEST MODE -- COMMAND WILL NOT BE EXECUTED");
                                else {
                                    try {
                                        pr = Runtime.getRuntime().exec(sb.toString());
                                    }
                                    catch (Exception e) {
                                        writeLog("Exception running command:"+sb.toString()+" message:"+e.getMessage());
                                    }
                                    if (pr != null)
                                        writeLog("Command executed. Exit value:"+pr.waitFor());
                                } // if testMode
                            } // if (aco.canFire
                        } // for iterator iActions  
                    } // if
                } // for Iterator iPattern
            } // while running
        }  // end of try
        catch (Exception e) {
            writeLog("Nonox terminating due to exception:"+e.getMessage());
        }
        
        writeLog("Nonox terminating");
    } // end of main()
    
    
    
    
    
    
    
    static class PatternConfig  {
        String patternName = null;
        String fileName = null;
        File f = null;
        String regexp = null;
        Pattern compiledPattern = null;
        BufferedReader br = null;
        long fileOpenTimestamp = 0; // timestamp when file reader was opened, so it could be periodically refreshed
        
        PatternConfig(String _patternName, String _fileName, boolean _tailMode, String _regexp)
        throws FileNotFoundException, IOException {
                patternName = _patternName.trim().toLowerCase();
                fileName = _fileName;
                f = new File(fileName);
                regexp = _regexp;
                compiledPattern = Pattern.compile(_regexp);
                reopen(_tailMode);
        }
        
        /**
         * Establishes a connection to the releated file. If the file is already bound, it closes and re-opens
         * the file. Useful to periodically renew file connections (e.g. in case the file is turned over
         * by a logrotate and the linkage to the new file lost to this application).
         */
        public void reopen(boolean _tailMode)
        throws FileNotFoundException, IOException {
            if (br != null) {
                writeLog("Closing file for periodic reopen:"+fileName);
                try { br.close(); }
                catch (IOException ioe) { }
            }
            // open the file
            writeLog("Opening file:"+fileName);
            br = new BufferedReader(new FileReader(f));
            fileOpenTimestamp = System.currentTimeMillis();
            // seek to EOF to "tail" the file and not reprocess it (would cause misfires if program were restarted at few times)
            if (_tailMode) {
                writeLog("In tail mode. Skipping to EOF of:"+fileName+" size:"+f.length());
                br.skip(f.length());
            }
        }
        
        public void reopen()
        throws FileNotFoundException, IOException {
            reopen(true);
        }
        
        
        public String toString() {
            return "Pattern:"+patternName+" bound to file:"+fileName+" with regexp:"+regexp;
        }
    }
    
    static class ActionConfig {
        String patternName;
        int thresholdCount;
        int timelimitSeconds;
        String command;
        int index;
        static int nextIndex = 0; // a quick way to get the index of this actionConfig when making a key that uses it
        
        ActionConfig(String _patternName, int _thresholdCount, int _timelimitSeconds, String _command) {
            patternName = _patternName.trim().toLowerCase();
            thresholdCount = _thresholdCount;
            timelimitSeconds = _timelimitSeconds;
            command = _command;
            index = nextIndex++;
        }
        
        public String toString() {
            return "Action bound to pattern:"+patternName+" threshold:"+thresholdCount+" time limit in seconds:"+timelimitSeconds+" Command:"+command;
        }
    }  // end of class ActionConfig
        
    static class ActionCounter {
        Stack<Long> timestamps;
        int howmany; 
        long maxAgeMsec;
        boolean fired;
        
        public ActionCounter(int _howMany, int _maxAgeSec) {
            timestamps = new Stack<Long>();
            howmany = _howMany;
            maxAgeMsec = _maxAgeSec * 1000;
            fired = false;
        }
        
        public void pushTimestamp(long _timestamp) {
            timestamps.push(new Long(_timestamp));
            // first trim the stack if it's full, by removing the oldest (bottom-most) item(s) if it's too big
            if (timestamps.size() > howmany)
                timestamps.removeElementAt(0);
//                timestamps.setSize(howmany);
        }
         
        public boolean canFire() {
            if (fired) return false;
            if (timestamps.size() < howmany) return false;
            Long tsL = (Long) timestamps.firstElement();
            System.out.println("oldest timestamp: "+tsL.longValue()+" msec "+tsL.longValue()/1000+" seconds "+tsL.longValue()/60000+" minutes"+"\nAGE of oldest timestamp in seconds:"+((System.currentTimeMillis()-tsL.longValue())/1000));
            System.out.println("Current system time: "+System.currentTimeMillis());  
            return (tsL.longValue() > (System.currentTimeMillis() - (maxAgeMsec)));
        }
    } // end of class ActionCounter
    

    /**
     * The reaper goes through the counter structure, and tosses out any counters that have no recent activity on record... 
     * that is, every logged timestamp that is expired and cannot contribute to firing an action rule.
     */
    static class Reaper extends Thread {
        long delayMsec;
        Hashtable<String, ActionCounter> counters;
        
        /**
         * @param _initialDelaySec The delay in seconds between runs of the Reaper thread (the thread may adjust this dynamically as it's running)
         * @param _counters The counters Hashtable to reap... this should be a Hashtable of ActionCounter objects
         */
        public Reaper(long _initialDelaySec, Hashtable<String, ActionCounter> _counters) {
            delayMsec = _initialDelaySec * 1000;
            counters = _counters;
        }
        public void run() {
            while (true) {
                writeLog("Reaper thread running. Reaper will run every "+delayMsec+" msec ("+delayMsec/1000/60+" minutes)");
                // do reaping
                
                try {
                    sleep(delayMsec);
                }
                catch (InterruptedException ie) { }
            }
        }
    }
    
    
    
} // end of class NoNox
