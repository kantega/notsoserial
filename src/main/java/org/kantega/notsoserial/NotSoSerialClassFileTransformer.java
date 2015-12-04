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

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;

/**
 *
 */
public class NotSoSerialClassFileTransformer implements ClassFileTransformer {

    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
        if(isObjectInputStream(className))  {
            ClassReader reader = new ClassReader(classfileBuffer);
            ClassWriter writer = new ClassWriter(0);
            ObjectInputStreamClassVisitor classVisitor = new ObjectInputStreamClassVisitor(writer);
            reader.accept(classVisitor, 0);
            return writer.toByteArray();
        }
        if (isAbstractClassResolver(className)) {
            ClassReader reader = new ClassReader(classfileBuffer);
            ClassWriter writer = new ClassWriter(0);
            AbstractClassResolverClassVisitor classVisitor = new AbstractClassResolverClassVisitor(writer);
            reader.accept(classVisitor, 0);
            return writer.toByteArray();
        }
        return null;
    }

    private boolean isObjectInputStream(String className) {
        return "java/io/ObjectInputStream".equals(className);
    }

    private boolean isAbstractClassResolver(String className) {
        return "org/jboss/marshalling/AbstractClassResolver".equals(className);
    }

}
