package org.kantega.invokerdefender;

import com.sun.tools.attach.AgentInitializationException;
import com.sun.tools.attach.AgentLoadException;
import com.sun.tools.attach.AttachNotSupportedException;
import org.junit.Test;

import javax.xml.transform.TransformerConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

/**
 *
 */
public class InvokerDefenderIT {

    @Test
    public void attachShouldWorkWithNoAgent() throws TransformerConfigurationException, IOException, ClassNotFoundException, AttachNotSupportedException, AgentLoadException, AgentInitializationException {



        byte[] ser = Files.readAllBytes(Paths.get("target").resolve("bytes.ser"));

        try {

            System.setProperty("pwned", "false");
            // Deserializing should flip pwned to true
            deserialize(ser);
        } catch (ClassCastException e) {
            // Ignore this exception, happens after exploit has effect
        }

        assertThat(System.getProperty("pwned"), is("true"));

    }



    private Object deserialize(byte[] ser) throws IOException, ClassNotFoundException {
        ObjectInputStream stream = new ObjectInputStream(new ByteArrayInputStream(ser));
        return stream.readObject();
    }

}
