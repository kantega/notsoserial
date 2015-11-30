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

import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import javax.xml.transform.TransformerConfigurationException;

import org.apache.commons.collections4.functors.InvokerTransformer;
import org.junit.Test;

import com.sun.tools.attach.AgentInitializationException;
import com.sun.tools.attach.AgentLoadException;
import com.sun.tools.attach.AttachNotSupportedException;

/**
 *
 */
public class ArrayWithAgentIT {

    @Test(expected=UnsupportedOperationException.class)
    public void attackShouldBePreventedWithAgent() throws TransformerConfigurationException, IOException, ClassNotFoundException, AttachNotSupportedException, AgentLoadException, AgentInitializationException {
        @SuppressWarnings({ "rawtypes", "unchecked" })
        InvokerTransformer[] ita = {new InvokerTransformer("a", null, null)};
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(ita);
        oos.flush();

        WithAgentIT.attachAgent();
        
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()));
        ois.readObject();
        fail("reading object was successful");
    }
}
