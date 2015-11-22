/*
 * Copyright 2015 Kantega AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.kantega.notsoserial;

import java.io.*;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

/**
 *
 */
public class DefaultNotSoSerial implements NotSoSerial {

    private final Set<String> blacklist = new HashSet<String>();

    private Set<String> whiteList = null;

    private PrintWriter dryRunWriter = null;

    private PrintWriter traceWriter = null;

    private Set<String> deserializingClasses = new ConcurrentSkipListSet<String>();

    public DefaultNotSoSerial() {
        blacklist.add(internalName("org.apache.commons.collections.functors.InvokerTransformer"));
        blacklist.add(internalName("org.apache.commons.collections4.functors.InvokerTransformer"));
        blacklist.add(internalName("org.apache.commons.collections.functors.InstantiateTransformer"));
        blacklist.add(internalName("org.apache.commons.collections4.functors.InstantiateTransformer"));
        blacklist.add(internalName("org.codehaus.groovy.runtime.ConvertedClosure"));
        blacklist.add(internalName("org.codehaus.groovy.runtime.MethodClosure"));
        blacklist.add(internalName("org.springframework.beans.factory.ObjectFactory"));
        blacklist.add(internalName("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl"));

        String blacklistProperty = System.getProperty("notsoserial.blacklist");
        if(blacklistProperty != null) {
            File blackListFile = new File(blacklistProperty);
            if(!blackListFile.exists()) {
                throw new IllegalArgumentException("Blacklist file specified by 'notsoserial.blacklist' does not exist: " + blackListFile);
            }
            blacklist.addAll(readClassesFromFile(blackListFile));
        }

        String whiteListProperty = System.getProperty("notsoserial.whitelist");
        if(whiteListProperty != null) {
            File whiteListFile = new File(whiteListProperty);
            if(!whiteListFile.exists()) {
                throw new IllegalArgumentException("Whitelist file specified by 'notsoserial.whitelist' does not exist: " + whiteListFile);

            }

            whiteList = readClassesFromFile(whiteListFile);
        }

        String dryRunPath = System.getProperty("notsoserial.dryrun");
        if(dryRunPath != null) {
            dryRunWriter = openWriter(dryRunPath);
        }

        String tracePath = System.getProperty("notsoserial.trace");
        if(tracePath != null) {
            traceWriter = openWriter(tracePath);
        }
    }

    private PrintWriter openWriter(String path) {
        File file = new File(path);
        try {
             return new PrintWriter(new FileWriter(file));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private Set<String> readClassesFromFile(File whiteListFile) {
        Set<String> whitelist = new HashSet<String>();

        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(whiteListFile));
            String line;

            whiteList = new HashSet<String>();
            while((line = br.readLine()) != null) {
                line = line.trim();
                if(!line.isEmpty()) {
                    whitelist.add(internalName(line));
                }
            }

            return whitelist;
        } catch (IOException e) {
            throw new RuntimeException("Could not read white list file "+ whiteListFile);
        } finally {
            if(br != null) {
                try {
                    br.close();
                } catch (IOException e) {
                    // Ignore
                }
            }
        }
    }

    private String internalName(String internalName) {
        return internalName.replace('.','/');
    }


    private boolean shouldReject(String className) {
        if (isBlacklisted(className)) {
            return true;
        }

        return whiteList != null && !isWhitelisted(className, whiteList);
    }

    private boolean isWhitelisted(String className, Set<String> whiteList) {
        return isPrefixMatch(className, whiteList);
    }

    private boolean isBlacklisted(String className) {
        return isPrefixMatch(className, blacklist);
    }

    private boolean isPrefixMatch(String className, Set<String> whiteList) {
        for (String prefix : whiteList) {
            if(className.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private boolean isDryRun() {
        return dryRunWriter != null;
    }

    private void registerDeserialization(String className) {
        if(!deserializingClasses.contains(className)) {
            deserializingClasses.add(className);
            String prettyName = className.replace('/', '.');
            dryRunWriter.println(prettyName);
            dryRunWriter.flush();
            if(traceWriter != null) {
                traceWriter.println("Deserialization of class " + prettyName +" (on " + new Date().toString() +")");
                boolean foundReadObject = false;
                for (StackTraceElement element : Thread.currentThread().getStackTrace()) {
                    if(foundReadObject) {
                        traceWriter.println("\t at " + element.getClassName() +"." + element.getMethodName());
                    } else if (element.getClassName().equals(ObjectInputStream.class.getName())
                            && element.getMethodName().equals("readObject")) {
                        foundReadObject = true;
                    }
                }
            }
        }
    }

    public void onBeforeResolveClass(String className) {
        if(isDryRun()) {
            registerDeserialization(className);
        } else {
            preventDeserialization(className);
        }
    }

    private void preventDeserialization(String className) {
        if(shouldReject(className.replace('.', '/'))) {
            throw new UnsupportedOperationException("Deserialization not allowed for class " + className.replace('/', '.'));
        }
    }
}
