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

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;

import java.io.*;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

/**
 *
 */
public class NotSoSerialClassFileTransformer implements ClassFileTransformer {

    public static final Set<String> blacklist = new HashSet<String>();

    private static Set<String> whiteList = null;

    private static PrintWriter dryRunWriter = null;

    private static PrintWriter traceWriter = null;

    private static Set<String> deserializingClasses = new ConcurrentSkipListSet<String>();

    static {
        blacklist.add(internalName("org.apache.commons.collections.functors.InvokerTransformer"));
        blacklist.add(internalName("org.apache.commons.collections4.functors.InvokerTransformer"));
        blacklist.add(internalName("org.apache.commons.collections.functors.InstantiateTransformer"));
        blacklist.add(internalName("org.apache.commons.collections4.functors.InstantiateTransformer"));
        blacklist.add(internalName("org.codehaus.groovy.runtime.ConvertedClosure"));
        blacklist.add(internalName("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl"));

        String classes = System.getProperty("notsoserial.custom.classes");
        if(classes != null) {
            for (String className : classes.split(",")) {
                className = className.trim();
                blacklist.add(className);
            }
        }

        String whiteListProperty = System.getProperty("notsoserial.whitelist");
        if(whiteListProperty != null) {
            File whiteListFile = new File(whiteListProperty);
            if(!whiteListFile.exists()) {
                throw new IllegalArgumentException("Whitelist file specified by 'notsoserial.whitelist' does not exist: " + whiteListFile);

            }

            NotSoSerialClassFileTransformer.whiteList = readWhiteList(whiteListFile);
        }

        String dryRunPath = System.getProperty("notsoserial.dryrun");
        if(dryRunPath != null) {
            File dryRunFile = new File(dryRunPath);
            try {
                dryRunWriter = new PrintWriter(new FileWriter(dryRunFile));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        String tracePath = System.getProperty("notsoserial.trace");
        if(tracePath != null) {
            File traceFile = new File(tracePath);
            try {
                traceWriter = new PrintWriter(new FileWriter(traceFile));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static Set<String> readWhiteList(File whiteListFile) {
        Set<String> whitelist = new HashSet<String>();

        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(whiteListFile));
            String line;

            NotSoSerialClassFileTransformer.whiteList = new HashSet<String>();
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

    private static String internalName(String internalName) {
        return internalName.replace('.','/');
    }

    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {


        if(isObjectInputStream(className))  {
            ClassReader reader = new ClassReader(classfileBuffer);
            ClassWriter writer = new ClassWriter(0);
            String callbackMethod = dryRunWriter != null ? "registerDeserialization" : "preventDeserialization";
            ObjectInputStreamClassVisitor classVisitor = new ObjectInputStreamClassVisitor(writer, callbackMethod);
            reader.accept(classVisitor, 0);
            return writer.toByteArray();
        }
        return null;
    }

    private boolean isObjectInputStream(String className) {
        return "java/io/ObjectInputStream".equals(className);
    }

    public static ObjectStreamClass registerDeserialization(ObjectStreamClass desc) {
        String className = desc.getName();
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
        return desc;
    }


    public static ObjectStreamClass preventDeserialization(ObjectStreamClass desc) {
        String className = desc.getName();
        if(shouldReject(className.replace('.','/'))) {
            throw new UnsupportedOperationException("Deserialization not allowed for class " + className.replace('/', '.'));
        }
        return desc;
    }

    private static boolean shouldReject(String className) {
        if (isBlacklisted(className)) {
            return true;
        }
        Set<String> whiteList = NotSoSerialClassFileTransformer.whiteList;

        return whiteList != null && !isWhitelisted(className, whiteList);
    }

    private static boolean isWhitelisted(String className, Set<String> whiteList) {
        return isPrefixMatch(className, whiteList);
    }

    private static boolean isBlacklisted(String className) {
        return isPrefixMatch(className, blacklist);
    }

    private static boolean isPrefixMatch(String className, Set<String> whiteList) {
        for (String prefix : whiteList) {
            if(className.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }
}
