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
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.PriorityQueue;
import java.util.Queue;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.junit.Assert.assertThat;
import static org.kantega.notsoserial.WithAgentIT.attachAgent;

/**
 *
 */
public class CustomNotSoSerialIT {

    private Path servicesPath;

    @Before
    public void before() throws IOException, URISyntaxException {
        URL resource = getClass().getResource("/META-INF/services/org.kantega.notsoserial.NotSoSerial");
        servicesPath = Paths.get(resource.toURI());
        Files.write(servicesPath, (getClass().getPackage().getName() +".CustomNotSoSerial").getBytes());
    }

    @After
    public void after() throws IOException {
        Files.write(servicesPath, new byte[0]);
    }
    @Test
    public void shouldCollectUsingCustomNotSoSerial() throws AgentInitializationException, AgentLoadException, AttachNotSupportedException, IOException, URISyntaxException, ClassNotFoundException {

        attachAgent();

        Queue<String> strings = (Queue<String>) deserialize(serialize(new PriorityQueue<String>(Arrays.asList("one", "two", "three"))));

        assertThat(CustomNotSoSerial.instance.getResolvedClasses(), hasItem(PriorityQueue.class.getName()));

    }

    private byte[] serialize(Object object) throws IOException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(bout);
        out.writeObject(object);
        return bout.toByteArray();
    }


    private Object deserialize(byte[] ser) throws IOException, ClassNotFoundException {
        ObjectInputStream stream = new ObjectInputStream(new ByteArrayInputStream(ser));
        return stream.readObject();
    }
}
