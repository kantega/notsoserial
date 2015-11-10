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
