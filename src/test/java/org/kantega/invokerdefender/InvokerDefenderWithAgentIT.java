package org.kantega.invokerdefender;

import com.sun.tools.attach.AgentInitializationException;
import com.sun.tools.attach.AgentLoadException;
import com.sun.tools.attach.AttachNotSupportedException;
import com.sun.tools.attach.VirtualMachine;
import org.junit.Test;

import javax.xml.transform.TransformerConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

/**
 *
 */
public class InvokerDefenderWithAgentIT {




    @Test
    public void attackShouldBePreventedWithAgent() throws TransformerConfigurationException, IOException, ClassNotFoundException, AttachNotSupportedException, AgentLoadException, AgentInitializationException {

        attachAgent();

        byte[] ser = Files.readAllBytes(Paths.get("target").resolve("bytes.ser"));

        try {
            System.setProperty("pwned", "false");
            // Deserializing should not flip pwned to true
            deserialize(ser);
        } catch (ClassCastException e) {
            // Ignore, happens after exploit effect

        } catch (UnsupportedOperationException e) {
            // The object should not be deserializable
            System.out.println();
        }

        assertThat(System.getProperty("pwned"), is("false"));
    }




    private void attachAgent() throws IOException, AttachNotSupportedException, AgentLoadException, AgentInitializationException {

        String name = ManagementFactory.getRuntimeMXBean().getName();
        String pid = name.substring(0, name.indexOf("@"));
        System.out.println(name);


        final VirtualMachine m = VirtualMachine.attach(pid);

        m.loadAgent("target/invoker-defender-1.0-SNAPSHOT.jar");
    }



    private Object deserialize(byte[] ser) throws IOException, ClassNotFoundException {
        ObjectInputStream stream = new ObjectInputStream(new ByteArrayInputStream(ser));
        return stream.readObject();
    }
}
