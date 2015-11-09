package org.kantega.invokerdefender;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

import static java.util.Arrays.asList;

/**
 *
 */
public class UnserializeVisitor extends ClassVisitor{

    private String serializableName = Type.getInternalName(Serializable.class);

    public UnserializeVisitor(ClassVisitor classVisitor) {
        super(Opcodes.ASM5, classVisitor);
    }

    @Override
    public void visit(int version, int access, String name, String signature, String supername, String[] interfaces) {
        super.visit(version, access, name, signature, supername, removeSerializable(interfaces));
    }

    private String[] removeSerializable(String[] interfaces) {
        if(interfaces == null) {
            return interfaces;
        }
        Set<String> interfaceNames = new HashSet<String>(interfaces.length);
        interfaceNames.addAll(asList(interfaces));
        interfaceNames.remove(serializableName);
        return interfaceNames.toArray(new String[interfaceNames.size()]);

    }

}
