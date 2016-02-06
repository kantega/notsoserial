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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

import javax.annotation.Nonnull;

/**
 *
 */
public class DefaultNotSoSerial implements NotSoSerial {

    private Set<String> blacklist = new HashSet<String>();

    private Set<String> whiteList = new HashSet<String>();

    private boolean dryRun = false;
    
    //Volatile as the act of setting them closes the previous class.
    private volatile PrintWriter detailWriter = null;

    //Volatile as the act of setting them closes the previous class.
    private volatile PrintWriter traceWriter = null;

    private Set<String> deserializingClasses = new ConcurrentSkipListSet<String>();

    public DefaultNotSoSerial() {
        blacklist.add(internalName("org.apache.commons.collections.functors.InvokerTransformer"));
        blacklist.add(internalName("org.apache.commons.collections4.functors.InvokerTransformer"));
        blacklist.add(internalName("org.apache.commons.collections.functors.InstantiateTransformer"));
        blacklist.add(internalName("org.apache.commons.collections4.functors.InstantiateTransformer"));
        blacklist.add(internalName("org.codehaus.groovy.runtime.ConvertedClosure"));
        blacklist.add(internalName("org.codehaus.groovy.runtime.MethodClosure"));
        blacklist.add(internalName("org.springframework.beans.factory.ObjectFactory"));
        blacklist.add(internalName("org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider"));
        blacklist.add(internalName("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl"));
        blacklist.add(internalName("org.apache.xalan.internal.xsltc.trax.TemplatesImpl"));

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

            whiteList.addAll(readClassesFromFile(whiteListFile));
        }

        String dryRunPath = System.getProperty("notsoserial.dryrun");
        if(dryRunPath != null) {
            dryRun = true;
            detailWriter = openWriter(dryRunPath);
        }

        String tracePath = System.getProperty("notsoserial.trace");
        if(tracePath != null) {
            traceWriter = openWriter(tracePath);
        }
    }
    
    public void setDetailWriter(PrintWriter dryRunWriter) {
        PrintWriter previous = this.detailWriter;
        this.detailWriter = detailWriter;
        
        if(previous != null) {
            previous.close();
        }
    }

    public void setTraceWriter(PrintWriter traceWriter) {
        PrintWriter previous = this.traceWriter;
        this.traceWriter = traceWriter;
        
        if(previous != null) {
            previous.close();
        }
    }
    
    public void setWhiteList(@Nonnull Set<String> whitelist) {
        if(whitelist == null) {
            throw new IllegalArgumentException("Null whitelist not supported");
        }
        
        this.whiteList = convertExternalToInternalSet(whitelist);
    }
    
    public void setBlackList(@Nonnull Set<String> blacklist) {
        if(blacklist == null) {
            throw new IllegalArgumentException("Null blacklist not supported");
        }
        this.blacklist = convertExternalToInternalSet(blacklist);
    }
    
    private Set<String> convertExternalToInternalSet(@Nonnull Set<String> externalSet) {
        Set<String> internalSet = new HashSet<String>(externalSet.size());
        for(String entry : externalSet) {
            internalSet.add(internalName(entry));
        }
        return internalSet;
    }
    
    private PrintWriter openWriter(String path) {
        File file = new File(path);
        try {
             return new PrintWriter(new FileWriter(file));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private Set<String> readClassesFromFile(File file) {
        Set<String> list = new HashSet<String>();

        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(file));
            String line;

            while((line = br.readLine()) != null) {
                line = line.trim();
                if(!line.isEmpty()) {
                    list.add(internalName(line));
                }
            }

            return list;
        } catch (IOException e) {
            throw new RuntimeException("Could not read white list file "+ file);
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

        return !isWhitelisted(className, whiteList);
    }

    private boolean isWhitelisted(String className, Set<String> whiteList) {
        if(whiteList.isEmpty()) {
            return true;
        }
        return isPrefixMatch(className, whiteList);
    }

    private boolean isBlacklisted(String className) {
        return isPrefixMatch(className, blacklist);
    }

    private boolean isPrefixMatch(String className, Set<String> whiteList) {
        synchronized(whiteList) {
            for (String prefix : whiteList) {
                if(className.startsWith(prefix)) {
                    return true;
                }
            }
        }
        return false;
    }

    private void registerDeserialization(String className) {
        if(!deserializingClasses.contains(className)) {
            deserializingClasses.add(className);
            String prettyName = className.replace('/', '.');
    
            if(traceWriter != null) {
                traceDeserializationStack("Deserialization of class " + prettyName +" (on " + new Date().toString() +")");
            }
            if(detailWriter != null) {
                detailWriter.println("Deserialization of class " + prettyName);
                detailWriter.flush();
            }
        }
    }

    private void traceDeserializationStack(String msg) {
        if(traceWriter == null) {
            return;
        }
        StringBuilder sb = msg != null ? new StringBuilder(msg + "\n") : new StringBuilder();
        boolean foundReadObject = false;
        for (StackTraceElement element : Thread.currentThread().getStackTrace()) {
            if(foundReadObject) {
                sb.append("\t at " + element.getClassName() +"." + element.getMethodName() +"\n");
            } else if (element.getClassName().equals(ObjectInputStream.class.getName())
                    && element.getMethodName().equals("readObject")) {
                foundReadObject = true;
            }
        }
        String result = sb.toString().trim();
        traceWriter.println(result); //print entire message simultaneously.
        traceWriter.flush();
    }

    public void onBeforeResolveClass(String className) {
        if(dryRun) {
            registerDeserialization(className);
        } else {
            preventDeserialization(className);
        }
    }

    private void preventDeserialization(String className) {
        if(shouldReject(className.replace('.', '/'))) {
            String msg = "Deserialization not allowed for class " + className.replace('/', '.') +" (on " + new Date().toString() +")";
            traceDeserializationStack(msg);
            throw new UnsupportedOperationException(msg);
        }
        else {
            registerDeserialization(className);
        }
    }
}
