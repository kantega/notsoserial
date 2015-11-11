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

import java.io.File;
import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.jar.JarFile;

/**
 *
 */
public class NotSoSerialAgent {

    public static void premain(String options, Instrumentation instrumentation) throws Exception {
        addTransformer(instrumentation);
    }

    public static void agentmain(String options, Instrumentation instrumentation) throws Exception {
        addTransformer(instrumentation);
    }

    private static void addTransformer(Instrumentation instrumentation) {
        injectBootstrapClasspath(instrumentation);
        instrumentation.addTransformer(new NotSoSerialClassFileTransformer());
    }

    private static void injectBootstrapClasspath(Instrumentation instrumentation) {

        try {
            URL resource = NotSoSerialAgent.class.getResource("/org/kantega/notsoserial/shaded/");

            String path = resource.toURI().getSchemeSpecificPart();
            path = path.substring("file:".length(), path.indexOf("!"));

            File file = new File(path);
            instrumentation.appendToBootstrapClassLoaderSearch(new JarFile(file));
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
