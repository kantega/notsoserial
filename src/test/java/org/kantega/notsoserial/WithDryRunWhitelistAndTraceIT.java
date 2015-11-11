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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Set;
import java.util.TreeSet;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

/**
 *
 */
public class WithDryRunWhitelistAndTraceIT {




    @Test
    public void shouldRecordClassesAsDeserialized() throws TransformerConfigurationException, IOException, ClassNotFoundException, AttachNotSupportedException, AgentLoadException, AgentInitializationException {

        System.setProperty("notsoserial.whitelist", "src/test/resources/whitelist.txt");
        System.setProperty("notsoserial.dryrun", "target/is-deserialized.txt");
        System.setProperty("notsoserial.trace", "target/deserialized-trace.txt");

        attachAgent();

        byte[] ser = Files.readAllBytes(Paths.get("target").resolve("bytes.ser"));

        try {
            System.setProperty("pwned", "false");
            // Deserializing should not flip pwned to true
            deserialize(ser);
        } catch (ClassCastException e) {
            // Ignore, happens after exploit effect

        }
        assertThat(System.getProperty("pwned"), is("true"));

        Set<String> deserialized = new TreeSet<String>(Files.readAllLines(Paths.get("target/is-deserialized.txt"),StandardCharsets.UTF_8));
        assertThat(deserialized, hasItem("org.apache.commons.collections4.functors.InvokerTransformer"));
        assertThat(deserialized, hasItem("java.util.PriorityQueue"));
    }




    private void attachAgent() throws IOException, AttachNotSupportedException, AgentLoadException, AgentInitializationException {

        String name = ManagementFactory.getRuntimeMXBean().getName();
        String pid = name.substring(0, name.indexOf("@"));
        System.out.println(name);


        final VirtualMachine m = VirtualMachine.attach(pid);

        m.loadAgent("target/notsoserial-1.0-SNAPSHOT.jar");
    }



    private Object deserialize(byte[] ser) throws IOException, ClassNotFoundException {
        ObjectInputStream stream = new ObjectInputStream(new ByteArrayInputStream(ser));
        return stream.readObject();
    }
}
