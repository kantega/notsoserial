package org.kantega.invokerdefender;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;

import java.io.*;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;
import java.util.HashSet;
import java.util.Set;

/**
 *
 */
public class DefenderClassFileTransformer implements ClassFileTransformer {

    public static final Set<String> unserialized = new HashSet<String>();

    private static Set<String> whiteList = null;

    private static PrintWriter dryRunWriter = null;

    private static Set<String> deserializingClasses = new HashSet<String>();

    static {
        unserialized.add(internalName("org.apache.commons.collections.functors.InvokerTransformer"));
        unserialized.add(internalName("org.apache.commons.collections4.functors.InvokerTransformer"));
        unserialized.add(internalName("org.codehaus.groovy.​runtime.​ConvertedClosure"));
        unserialized.add(internalName("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl"));
        String classes = System.getProperty("invoker.defender.custom.classes");
        if(classes != null) {
            for (String className : classes.split(",")) {
                className = className.trim();
                unserialized.add(className);
            }
        }

        String whiteListProperty = System.getProperty("invoker.defender.whitelist");
        if(whiteListProperty != null) {
            File whiteListFile = new File(whiteListProperty);
            if(!whiteListFile.exists()) {
                throw new IllegalArgumentException("Whitelist file specified by 'invoker.defender.whitelist' does not exist: " + whiteListFile);

            }

            DefenderClassFileTransformer.whiteList = readWhiteList(whiteListFile);
        }

        String dryRunPath = System.getProperty("invoker.defender.dryrun");
        if(dryRunPath != null) {
            File dryRunFile = new File(dryRunPath);
            try {
                dryRunWriter = new PrintWriter(new FileWriter(dryRunFile));
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

            DefenderClassFileTransformer.whiteList = new HashSet<String>();
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
        if(shouldUnserialize(className, loader, classfileBuffer)) {
            ClassReader reader = new ClassReader(classfileBuffer);
            ClassWriter writer = new ClassWriter(0);
            ClassVisitor classVisitor = dryRunWriter != null ? new DryrunVisitor(writer, className) : new UnserializeVisitor(writer);
            reader.accept(classVisitor, 0);
            return writer.toByteArray();
        }
        return classfileBuffer;
    }

    public static void registerDeserialization(String className) {
        Set<String> deserializingClasses = DefenderClassFileTransformer.deserializingClasses;
        if(!deserializingClasses.contains(className)) {
            deserializingClasses.add(className);
            dryRunWriter.println(className.replace('/', '.'));
            dryRunWriter.flush();
        }
    }
    private boolean shouldUnserialize(String className, ClassLoader loader, byte[] classfileBuffer) {
        if(className == null || classfileBuffer == null) {
            return false;
        }
        Set<String> whiteList = DefenderClassFileTransformer.whiteList;
        if(whiteList != null) {
            for (String prefix : whiteList) {
                if(className.startsWith(prefix)) {
                    return false;
                }
            }
            return true;
        } else {
            return unserialized.contains(className);
        }
    }
}
